<?php

require_once __DIR__ . '/vendor/autoload.php';

use Bigcommerce\Api\Client as Bigcommerce;
use Firebase\JWT\JWT;
use Guzzle\Http\Client;
use Handlebars\Handlebars;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Silex\Provider\FormServiceProvider;
/*use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\SubmitType;
use Silex\Provider\TwigServiceProvider;
use Symfony\Bridge\Twig;
use Silex\Provider\SecurityServiceProvider;*/



// Load from .env file
$dotenv = new Dotenv\Dotenv(__DIR__);
$dotenv->load();

$app = new Application();
$app['debug'] = true;

$app->register(new FormServiceProvider());
$app->register(new Silex\Provider\TwigServiceProvider(), array(
	'twig.path' => __DIR__.'/templates',
	'twig.class_path' => __DIR__ . '/vendor/twig/lib',
));



$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
	'db.options' => array (
		'driver'    => 'pdo_mysql',
		'host'      => mysqlHost(),
		'dbname'    => mysqlDatabase(),
		'user'      => mysqlUser(),
		'password'  => mysqlPassword(),
		'charset'   => 'utf8mb4',
	),
));

$app->get('/', function (Request $request) use ($app) {
	$id = 1;
	$sql = "SELECT * FROM cms_block WHERE id = ?";
	$post = $app['db']->fetchAssoc($sql, array((int) $id));

	$data = ['title' => $post['title'], 'content' => $post['content']];

	return $app['twig']->render('form.twig', array('data' => $data));
});

$app->get('/blog/{id}', function (Silex\Application $app, $id) {
	$sql = "SELECT * FROM cms_block WHERE id = ?";
	$post = $app['db']->fetchAssoc($sql, array((int) $id));

	return  $post['content'];
});

$app->post('/save', function (Request $request) use ($app) {
	$id =1 ;
	$title = $request->get('title');
	$content = $request->get('content');

	$sql = "UPDATE `cms_block` SET `title` = ?, `content` = ? WHERE `cms_block`.`id` = ?;";
	$app['db']->executeUpdate($sql, array($title,$content, (int) $id));
	return new Response(json_encode(['status'=> 'success']), 200);
});
$app->get('/load', function (Request $request) use ($app) {

	$data = verifySignedRequest($request->get('signed_payload'));
	if (empty($data)) {
		return 'Invalid signed_payload.';
	}
	$redis = redisServer();
	$key = getUserKey($data['store_hash'], $data['user']['email']);
	$user = json_decode($redis->get($key), true);
	if (empty($user)) {
		$user = $data['user'];
		$redis->set($key, json_encode($user, true));
	}
	/**/
	$id = 1;
	$sql = "SELECT * FROM cms_block WHERE id = ?";
	$post = $app['db']->fetchAssoc($sql, array((int) $id));

	$data = ['title' => $post['title'], 'content' => $post['content']];

	return $app['twig']->render('form.twig', array('data' => $data));
	/**/
});

$app->get('/auth/callback', function (Request $request) use ($app) {
	$redis = redisServer();

	$payload = array(
		'client_id' => clientId(),
		'client_secret' => clientSecret(),
		'redirect_uri' => callbackUrl(),
		'grant_type' => 'authorization_code',
		'code' => $request->get('code'),
		'scope' => $request->get('scope'),
		'context' => $request->get('context'),
	);

	$client = new Client(bcAuthService());
	$req = $client->post('/oauth2/token', array(), $payload, array(
		'exceptions' => false,
	));
	$resp = $req->send();

	if ($resp->getStatusCode() == 200) {
		$data = $resp->json();
		list($context, $storeHash) = explode('/', $data['context'], 2);
		$key = getUserKey($storeHash, $data['user']['email']);

		// Store the user data and auth data in our key-value store so we can fetch it later and make requests.
		$redis->set($key, json_encode($data['user'], true));
		$redis->set("stores/{$storeHash}/auth", json_encode($data));

		return 'Hello ' . json_encode($data);
	} else {
		return 'Something went wrong... [' . $resp->getStatusCode() . '] ' . $resp->getBody();
	}

});

// Endpoint for removing users in a multi-user setup
$app->get('/remove-user', function(Request $request) use ($app) {
	$data = verifySignedRequest($request->get('signed_payload'));
	if (empty($data)) {
		return 'Invalid signed_payload.';
	}

	$key = getUserKey($data['store_hash'], $data['user']['email']);
	$redis = redisServer();
	$redis->del($key);
	return '[Remove User] '.$data['user']['email'];
});

/**
 * GET /storefront/{storeHash}/customers/{jwtToken}/recently_purchased.html
 * Fetches the "Recently Purchased Products" HTML block and displays it in the frontend.
 */
$app->get('/storefront/{storeHash}/customers/{jwtToken}/recently_purchased.html', function ($storeHash, $jwtToken) use ($app) {
	$headers = ['Access-Control-Allow-Origin' => '*'];
	try {
		// First let's get the customer's ID from the token and confirm that they're who they say they are.
		$customerId = getCustomerIdFromToken($jwtToken);

		// Next let's initialize the BigCommerce API for the store requested so we can pull data from it.
		configureBCApi($storeHash);

		// Generate the recently purchased products HTML
		$recentlyPurchasedProductsHtml = getRecentlyPurchasedProductsHtml($storeHash, $customerId);

		// Now respond with the generated HTML
		$response = new Response($recentlyPurchasedProductsHtml, 200, $headers);
	} catch (Exception $e) {
		error_log("Error occurred while trying to get recently purchased items: {$e->getMessage()}");
		$response = new Response("", 500, $headers); // Empty string here to make sure we don't display any errors in the storefront.
	}

	return $response;
});

/**
 * Gets the HTML block that displays the recently purchased products for a store.
 * @param string $storeHash
 * @param string $customerId
 * @return string HTML content to display in the storefront
 */
function getRecentlyPurchasedProductsHtml($storeHash, $customerId)
{
	$redis = redisServer();
	$cacheKey = "stores/{$storeHash}/customers/{$customerId}/recently_purchased_products.html";
	$cacheLifetime = 60 * 5; // Set a 5 minute cache lifetime for this HTML block.

	// First let's see if we can find he HTML block in the cache so we don't have to reach out to BigCommerce's servers.
	$cachedContent = json_decode($redis->get($cacheKey));
	if (!empty($cachedContent) && (int)$cachedContent->expiresAt > time()) { // Ensure the cache has not expired as well.
		return $cachedContent->content;
	}

	// Whelp looks like we couldn't find the HTML block in the cache, so we'll have to compile it ourselves.
	// First let's get all the customer's recently purchased products.
	$products = getRecentlyPurchasedProducts($customerId);

	// Render the template with the recently purchased products fetched from the BigCommerce server.
	$htmlContent =  (new Handlebars())->render(
		file_get_contents('templates/recently_purchased.html'),
		['products' => $products]
	);
	$htmlContent = str_ireplace('http', 'https', $htmlContent); // Ensures we have HTTPS links, which for some reason we don't always get.

	// Save the HTML content in the cache so we don't have to reach out to BigCommece's server too often.
	$redis->set($cacheKey, json_encode([ 'content' => $htmlContent, 'expiresAt' => time() + $cacheLifetime]));

	return $htmlContent;
}

/**
 * Look at each of the customer's orders, and each of their order products and then pull down each product resource
 * that was purchased.
 * @param string $customerId ID of the customer that we want to retrieve the recently purchased products list for.
 * @return array<Bigcommerce\Resources\Product> An array of products from the BigCommerce API
 */
function getRecentlyPurchasedProducts($customerId)
{
	$products = [];

	foreach(Bigcommerce::getOrders(['customer_id' => $customerId]) as $order) {
		foreach (Bigcommerce::getOrderProducts($order->id) as $orderProduct) {
			array_push($products, Bigcommerce::getProduct($orderProduct->product_id));
		}
	}

	return $products;
}

/**
 * Configure the static BigCommerce API client with the authorized app's auth token, the client ID from the environment
 * and the store's hash as provided.
 * @param string $storeHash Store hash to point the BigCommece API to for outgoing requests.
 */
function configureBCApi($storeHash)
{
	Bigcommerce::configure(array(
		'client_id' => clientId(),
		'auth_token' => getAuthToken($storeHash),
		'store_hash' => $storeHash
	));
}

/**
 * @param string $storeHash store's hash that we want the access token for
 * @return string the oauth Access (aka Auth) Token to use in API requests.
 */
function getAuthToken($storeHash)
{
	$redis = redisServer();
	$authData = json_decode($redis->get("stores/{$storeHash}/auth"));
	return $authData->access_token;
}

/**
 * @param string $jwtToken	customer's JWT token sent from the storefront.
 * @return string customer's ID decoded and verified
 */
function getCustomerIdFromToken($jwtToken)
{
	$signedData = JWT::decode($jwtToken, clientSecret(), array('HS256', 'HS384', 'HS512', 'RS256'));
	return $signedData->customer->id;
}

/**
 * This is used by the `GET /load` endpoint to load the app in the BigCommerce control panel
 * @param string $signedRequest Pull signed data to verify it.
 * @return array|null null if bad request, array of data otherwise
 */
function verifySignedRequest($signedRequest)
{
	list($encodedData, $encodedSignature) = explode('.', $signedRequest, 2);

	// decode the data
	$signature = base64_decode($encodedSignature);
	$jsonStr = base64_decode($encodedData);
	$data = json_decode($jsonStr, true);

	// confirm the signature
	$expectedSignature = hash_hmac('sha256', $jsonStr, clientSecret(), $raw = false);
	if (!hash_equals($expectedSignature, $signature)) {
		error_log('Bad signed request from BigCommerce!');
		return null;
	}
	return $data;
}

/**
 * @return string Get the app's client ID from the environment vars
 */
function clientId()
{
	$clientId = getenv('BC_CLIENT_ID');
	return $clientId ?: '';
}

/**
 * @return string Get the app's client secret from the environment vars
 */
function clientSecret()
{
	$clientSecret = getenv('BC_CLIENT_SECRET');
	return $clientSecret ?: '';
}

/**
 * @return string Get the callback URL from the environment vars
 */
function callbackUrl()
{
	$callbackUrl = getenv('BC_CALLBACK_URL');
	return $callbackUrl ?: '';
}

/**
 * @return string Get auth service URL from the environment vars
 */
function bcAuthService()
{
	$bcAuthService = getenv('BC_AUTH_SERVICE');
	return $bcAuthService ?: '';
}

//Redis
function redisHost()
{
	$host = getenv('REDIS_HOST');
	return $host ?: '127.0.0.1';
}

function redisPort()
{
	$port = getenv('REDIS_PORT');
	return $port ?: '6379';
}

function redisPassword()
{
	$password = getenv('REDIS_PASSWORD');
	return $password ?: null;
}

function redisDatabase()
{
	$password = getenv('REDIS_DATABASE');
	return $password ?: '0';
}

function getUserKey($storeHash, $email)
{
	return "kitty.php:$storeHash:$email";
}

//Mysql
function mysqlHost()
{
	$host = getenv('MYSQL_HOST');
	return $host ?: 'localhost';
}

function mysqlUser()
{
	$port = getenv('MYSQL_USER');
	return $port ?: 'root';
}

function mysqlPassword()
{
	$password = getenv('MYSQL_PASSWORD');
	return $password ?: null;
}

function mysqlDatabase()
{
	$password = getenv('MYSQL_DATABASE');
	return $password ?: '0';
}

function redisServer()
{
	$redis_host = redisHost();
	$redis_port = redisPort();
	$redis_password = redisPassword();
	$redis_database = redisDatabase();

	$redis = new Credis_Client($redis_host, $redis_port, null, "none", $redis_database, $redis_password);
	return $redis;
}

$app->run();
