<?php

namespace Drupal\helfi_helsinki_profiili;

use Drupal\Component\Serialization\Json;
use Drupal\Component\Utility\Xss;
use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\TempStore\TempStoreException;
use Drupal\grants_handler\ApplicationHandler;
use Drupal\helfi_api_base\Environment\EnvironmentResolverInterface;
use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent;
use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliOperationEvent;
use Drupal\openid_connect\OpenIDConnectSession;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Integrate HelsinkiProfiili data to Drupal User.
 */
class HelsinkiProfiiliUserData {

  /**
   * The openid_connect.session service.
   *
   * @var \Drupal\openid_connect\OpenIDConnectSession
   */
  protected OpenIDConnectSession $openidConnectSession;

  /**
   * The HTTP client.
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected ClientInterface $httpClient;

  /**
   * The logger channel factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected LoggerChannelInterface $logger;

  /**
   * Cached data that is fetched from external sources.
   *
   * @var array
   */
  protected array $userProfileData;

  /**
   * Drupal\Core\Session\AccountProxyInterface definition.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $currentUser;

  /**
   * Request stack for session access.
   *
   * @var \Drupal\Core\Http\RequestStack
   */
  protected RequestStack $requestStack;

  /**
   * Store user roles for helsinki profile users.
   *
   * @var array
   */
  protected array $hpUserRoles;

  /**
   * User roles for form administration.
   *
   * @var array
   */
  protected array $hpAdminRoles;

  /**
   * The environment resolver.
   *
   * @var \Drupal\helfi_api_base\Environment\EnvironmentResolverInterface
   */
  private EnvironmentResolverInterface $environmentResolver;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  private EntityTypeManagerInterface $entityManager;

  /**
   * Store details about oidc issuer.
   *
   * @var array
   */
  private array $openIdConfiguration;

  /**
   * Request cache.
   *
   * @var array
   */
  private array $cachedData = [];

  /**
   * Debug status.
   *
   * @var bool
   */
  protected bool $debug;

  /**
   * Endpoint for api tokens.
   *
   * @var string
   */
  protected string $apiTokenEndpoint;

  /**
   * The event dispatcher service.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected EventDispatcherInterface $eventDispatcher;

  /**
   * The event dispatcher service.
   *
   * @var \Drupal\Core\Config\Config
   */
  protected Config $config;

  /**
   * Constructs a HelsinkiProfiiliUser object.
   *
   * @param \Drupal\openid_connect\OpenIDConnectSession $openid_connect_session
   *   The openid_connect.session service.
   * @param \GuzzleHttp\ClientInterface $http_client
   *   The HTTP client.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger channel factory.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   Current user session.
   * @param \Drupal\Core\Http\RequestStack $requestStack
   *   Access session store.
   * @param \Drupal\helfi_api_base\Environment\EnvironmentResolverInterface $environmentResolver
   *   Where are we?
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $eventDispatcher
   *   Dispatch events.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Config factory.
   */
  public function __construct(
    OpenIDConnectSession $openid_connect_session,
    ClientInterface $http_client,
    LoggerChannelFactoryInterface $logger_factory,
    AccountProxyInterface $currentUser,
    RequestStack $requestStack,
    EnvironmentResolverInterface $environmentResolver,
    EntityTypeManagerInterface $entityTypeManager,
    EventDispatcherInterface $eventDispatcher,
    ConfigFactoryInterface $configFactory
  ) {
    $this->openidConnectSession = $openid_connect_session;
    $this->httpClient = $http_client;
    $this->environmentResolver = $environmentResolver;

    $this->logger = $logger_factory->get('helsinki_profiili');
    $this->eventDispatcher = $eventDispatcher;
    $this->currentUser = $currentUser;
    $this->requestStack = $requestStack;
    $this->entityManager = $entityTypeManager;

    $this->openIdConfiguration = [];

    $this->config = $configFactory->get('helfi_helsinki_profiili.settings');
    $rolesConfig = $this->config->get('roles');

    if (!empty($rolesConfig['hp_user_roles'])) {
      $this->hpUserRoles = $rolesConfig['hp_user_roles'];
    }
    else {
      $this->hpUserRoles = [];
    }
    if (!empty($rolesConfig['admin_user_roles'])) {
      $this->hpAdminRoles = $rolesConfig['admin_user_roles'];
    }
    else {
      $this->hpAdminRoles = [];
    }

    // Set api endpoint url.
    $this->setApiTokenEndpoint(getenv('TUNNISTAMO_API_TOKEN_ENDPOINT'));

    $debug = getenv('DEBUG');

    if ($debug == 'true' || $debug === TRUE) {
      $this->debug = TRUE;
    }
    else {
      $this->debug = FALSE;
    }
  }

  /**
   * Figure out if user is authed.
   *
   * @return bool
   *   If user is authenticated externally.
   */
  public function isAuthenticatedExternally(): bool {
    return !($this->openidConnectSession->retrieveIdToken() === NULL);
  }

  /**
   * Get user authentication level from suomifi / helsinkiprofile.
   *
   * @return string
   *   Authentication level to be tested.
   *
   * @todo When auth levels are set in HP, check that these match.
   */
  public function getAuthenticationLevel(): string {
    $authLevel = 'noAuth';

    $userData = $this->getUserData();

    if ($userData == NULL) {
      return $authLevel;
    }

    if ($userData['loa'] == 'substantial') {
      return 'strong';
    }
    if ($userData['loa'] == 'low') {
      return 'weak';
    }

    return $authLevel;
  }

  /**
   * Return parsed JWT token data from openid.
   *
   * @return array
   *   Token data for authenticated user.
   */
  public function getTokenData(): array {
    return $this->parseToken($this->openidConnectSession->retrieveIdToken());
  }

  /**
   * Set user data to private store.
   *
   * @param array $userData
   *   Userdata retrieved from HP.
   */
  public function setUserData(array $userData): bool {
    return $this->setToCache('userData', $userData);
  }

  /**
   * Get user data from tempstore.
   *
   * @return array
   *   Userdata from tempstore.
   */
  public function getUserData(): array {
    return $this->getTokenData();
  }

  /**
   * Get access tokens from helsinki profiili.
   *
   * @return array|null
   *   Accesstokens or null.
   *
   * @throws \Drupal\helfi_helsinki_profiili\TokenExpiredException
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function getApiAccessTokens(): ?array {
    // Access token to get api access tokens in next step.
    $accessToken = $this->openidConnectSession->retrieveAccessToken();

    if ($accessToken == NULL) {
      throw new TokenExpiredException('No token data available');
    }

    // Use access token to fetch profiili token from token service.
    return $this->getHelsinkiProfiiliToken($accessToken);
  }

  /**
   * Get user profile data from tunnistamo.
   *
   * @param bool $refetch
   *   Non false value will bypass caching.
   *
   * @return array|null
   *   User profile data.
   *
   * @throws \Drupal\helfi_helsinki_profiili\TokenExpiredException
   */
  public function getUserProfileData(bool $refetch = FALSE): ?array {
    // Access token to get api access tokens in next step.
    $accessToken = $this->openidConnectSession->retrieveAccessToken();

    if ($accessToken == NULL) {
      return NULL;
    }

    if (!$refetch && $this->isCached('myProfile')) {
      return $this->getFromCache('myProfile');
    }

    // End point to access profile data.
    $endpoint = getenv('USERINFO_PROFILE_ENDPOINT');
    // Get query.
    $query = $this->graphqlQuery();

    try {
      // Use access token to fetch profiili token from token service.
      $apiAccessToken = $this->getHelsinkiProfiiliToken($accessToken);

      $headers = [
        'Content-Type' => 'application/json',
      ];
      // Use api access token if set, if not, return NULL.
      if (isset($apiAccessToken['access_token'])) {
        $headers['Authorization'] = 'Bearer ' . $apiAccessToken["access_token"];
      }
      else {
        // No point going further if no token is received.
        return NULL;
      }

      // Get profiili data with api access token.
      $response = $this->httpClient->request('POST', $endpoint, [
        'headers' => $headers,
        'json' => [
          'query' => $query,
        ],
      ]);
      $this->dispatchOperationEvent('PROFILE DATA FETCH');

      $json = $response->getBody()->getContents();
      $body = Json::decode($json);
      $data = $body['data'];

      if (!empty($body['errors'])) {
        foreach ($body['errors'] as $error) {
          $this->logger->error(
            '/userinfo endpoint threw errorcode %ecode: @error',
            [
              '%ecode' => $error['extensions']['code'],
              '@error' => $error['message'],
            ]
          );
        }
        throw new ProfileDataException('No profile data found');
      }
      else {
        $this->logger->notice('User %user got their HelsinkiProfiili data form endpoint', [
          '%user' => $this->currentUser->getDisplayName(),
        ]);
      }

      $filteredData = $this->filterData($data);
      $modifiedData = $this->checkPrimaryFields($filteredData);

      // Set profile data to cache so that no need to fetch more data.
      $this->setToCache('myProfile', $modifiedData);
      return $modifiedData;
    }
    catch (ClientException | ServerException $e) {
      $this->dispatchExceptionEvent($e);
      $this->logger->error(
        '/userinfo endpoint threw errorcode %ecode: @error',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
      );

      return NULL;
    }
    catch (TempStoreException $e) {
      $this->dispatchExceptionEvent($e);
      $this->logger->error(
        'Caching userprofile data failed',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
      );
    }
    catch (GuzzleException $e) {
      $this->dispatchExceptionEvent($e);
    }
    catch (ProfileDataException $e) {
      $this->dispatchExceptionEvent($e);
      $this->logger->error(
        $e->getMessage()
      );

      return NULL;
    }

    return NULL;
  }

  /**
   * Get query params for profile token.
   *
   * Dev/test use api-test, others per env.
   *
   * @return string[]
   *   String array containing token parameters.
   */
  private function getProfileTokenParams(): array {
    $appEnv = ApplicationHandler::getAppEnv();

    $endpointAudience = 'profile-api-test';

    if ($appEnv === 'PROD') {
      $endpointAudience = 'profile-api';
    }
    if ($appEnv === 'STAGE') {
      $endpointAudience = 'profile-api-stage';
    }

    return [
      'audience' => $endpointAudience,
      'grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket',
      'permission' => '#access',
    ];
  }

  /**
   * Fetch proper tokens from api-tokens endopoint.
   *
   * @param string $accessToken
   *   Token from authorization service.
   *
   * @return array|null
   *   Token data
   *
   * @throws \Drupal\helfi_helsinki_profiili\TokenExpiredException
   */
  private function getHelsinkiProfiiliToken(string $accessToken): ?array {
    try {
      $oid_config = $this->getOpenIdConfiguration();

      $response = $this->httpClient->request('POST', $oid_config["token_endpoint"], [
        'headers' => [
          'Authorization' => 'Bearer ' . $accessToken,
        ],
        'form_params' => $this->getProfileTokenParams(),
      ]);
      $body = $response->getBody()->getContents();

      if (strlen($body) < 5) {
        throw new ProfileDataException('No data from profile endpoint');
      }
      return Json::decode($body);
    }
    catch (ProfileDataException $profileDataException) {
      $this->dispatchExceptionEvent($profileDataException);
      $this->logger->error('Trying to get tokens from api-tokens endpoint, got empty body: @error', ['@error' => $profileDataException->getMessage()]);
      return NULL;
    }
    catch (GuzzleException | \Exception $e) {
      $this->dispatchExceptionEvent($e);
      $this->logger->error(
        'Error retrieving access token %ecode: @error',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
      );
      throw new TokenExpiredException($e->getMessage());
    }
  }

  /**
   * Build query for profile.
   *
   * @return string
   *   Graphql query.
   */
  protected function graphqlQuery(): string {
    return <<<'GRAPHQL'
      query MyProfileQuery {
        myProfile {
          id
          firstName
          lastName
          nickname
          language
          primaryAddress {
            id
            primary
            address
            postalCode
            city
            countryCode
            addressType
          }
          addresses {
            edges {
              node {
                primary
                id
                address
                postalCode
                city
                countryCode
                addressType
              }
            }
          }
          primaryEmail {
            id
            email
            primary
            emailType
          }
          emails {
            edges {
              node {
                primary
                id
                email
                emailType
              }
            }
          }
          primaryPhone {
            id
            phone
            primary
            phoneType
          }
          phones {
            edges {
              node {
                primary
                id
                phone
                phoneType
              }
            }
          }
          verifiedPersonalInformation {
            firstName
            lastName
            givenName
            nationalIdentificationNumber
            municipalityOfResidence
            municipalityOfResidenceNumber
            permanentAddress {
              streetAddress
              postalCode
              postOffice
            }
            temporaryAddress {
              streetAddress
              postalCode
              postOffice
            }
            permanentForeignAddress {
              streetAddress
              additionalAddress
              countryCode
            }
          }
        }
      }
      GRAPHQL;
  }

  /**
   * Parse JWT token.
   *
   * @param string $token
   *   The encoded ID token containing the user data.
   *
   * @return array
   *   The parsed JWT token or the original string.
   */
  public function parseToken(string $token): array {
    $parts = explode('.', $token, 3);
    if (count($parts) === 3) {
      $decoded = Json::decode(base64_decode($parts[1]));
      if (is_array($decoded)) {
        return $decoded;
      }
    }
    return [];
  }

  /**
   * Whether or not we have made this query?
   *
   * @param string $key
   *   Used key for caching.
   *
   * @return bool
   *   Is this cached?
   */
  public function clearCache($key = ''): bool {
    try {
      // $session = $this->requestStack->getCurrentRequest()->getSession();
      // $session->clear();
      return TRUE;
    }
    catch (\Exception $e) {
      $this->dispatchExceptionEvent($e);
      return FALSE;
    }
  }

  /**
   * Whether or not we have made this query?
   *
   * @param string|null $key
   *   Used key for caching.
   *
   * @return bool
   *   Is this cached?
   */
  private function isCached(?string $key): bool {
    $session = $this->requestStack->getCurrentRequest()->getSession();

    $cacheData = $session->get($key);
    return !is_null($cacheData);
  }

  /**
   * Get item from cache.
   *
   * @param string $key
   *   Key to fetch from tempstore.
   *
   * @return array|null
   *   Data in cache or null
   */
  private function getFromCache(string $key): array|null {
    $session = $this->requestStack->getCurrentRequest()->getSession();
    return !empty($session->get($key)) ? $session->get($key) : NULL;
  }

  /**
   * Add item to cache.
   *
   * @param string $key
   *   Used key for caching.
   * @param array $data
   *   Cached data.
   *
   * @return bool
   *   Did save succeed?
   */
  private function setToCache(string $key, array $data): bool {
    $session = $this->requestStack->getCurrentRequest()->getSession();

    $session->set($key, $data);
    return TRUE;
  }

  /**
   * Fill primaryPhone field from edge nodes, if it is missing.
   *
   * @param array $data
   *   Data array.
   *
   * @return array
   *   Modified array
   */
  public function checkPrimaryFields(array $data): array {
    static $fieldMapping = [
      'phone' => [
        'primary_field_key' => 'primaryPhone',
        'field_key' => 'phones',
      ],
      'email' => [
        'primary_field_key' => 'primaryEmail',
        'field_key' => 'emails',
      ],
      'address' => [
        'primary_field_key' => 'primaryAddress',
        'field_key' => 'addresses',
      ],
    ];

    foreach ($fieldMapping as $mapping) {
      [
        'primary_field_key' => $primaryFieldKey,
        'field_key' => $fieldKey,
      ] = $mapping;

      $primaryField = $data['myProfile'][$primaryFieldKey];
      if ($primaryField === NULL) {
        /*
         * Loop the edges. Get first node with verified flag, or
         * the first edge if none is verified.
         */
        foreach ($data['myProfile'][$fieldKey]['edges'] as $edge) {
          if ($edge['node']['primary']) {
            $primaryField = $edge['node'];
            break;
          }
        }

        // No primary flagged. Try to get first edge number.
        if ($primaryField === NULL) {
          $primaryField = $data['myProfile'][$fieldKey]['edges'][0]['node'] ?? NULL;
        }

        // If we have a edge, let's add it to the data array.
        if ($primaryField !== NULL) {
          $data['myProfile'][$primaryFieldKey] = $primaryField;
        }
      }
    }

    return $data;
  }

  /**
   * Runs the array items through Xss::filter function.
   *
   * @param array $data
   *   Input array.
   *
   * @return array
   *   Filtered data.
   */
  public function filterData(array $data) {
    // Make sure that data coming from HP is sanitized and does not contain
    // anything worth removing.
    array_walk_recursive(
      $data,
      function (&$item) {
        if (is_string($item)) {
          $item = Xss::filter($item);
        }
      }
    );

    return $data;
  }

  /**
   * Get current user data.
   *
   * @return \Drupal\Core\Session\AccountProxyInterface
   *   Current user.
   */
  public function getCurrentUser(): AccountProxyInterface {
    return $this->currentUser;
  }

  /**
   * Get roles of the current user.
   *
   * @return array
   *   Roles.
   */
  public function getCurrentUserRoles(): array {
    return $this->currentUser->getRoles();
  }

  /**
   * Get user roles that have helsinki profile authentication.
   *
   * @return array
   *   Helsinki profiili user roles.
   */
  public function getHpUserRoles(): array {
    return $this->hpUserRoles;
  }

  /**
   * Get admin roles.
   *
   * @return array
   *   Helsinki profiili admin roles.
   */
  public function getAdminRoles(): array {
    return $this->hpAdminRoles;
  }

  /**
   * Get openid configurations.
   *
   * @return array
   *   Open id config from endpoint.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function getOpenIdConfiguration(): array {
    if (!$this->openIdConfiguration) {
      $this->openIdConfiguration = $this->getOpenidConfigurationFromIssuer();
    }
    return $this->openIdConfiguration;
  }

  /**
   * Get issuer configs from server.
   *
   * @return array
   *   Config from env.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function getOpenidConfigurationFromIssuer(): array {
    return Json::decode(
      $this->httpClient->request(
        'GET',
        sprintf('%s/.well-known/openid-configuration/', $this->getTunnistamoEnvUrl())
      )->getBody()
    );
  }

  /**
   * Get jwks keys from issuer.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function getJwks() {
    $config = $this->getOpenIdConfiguration();

    $response = $this->httpClient->request(
      'GET',
      $config["jwks_uri"]
    );

    return Json::decode($response->getBody()->getContents());
  }

  /**
   * Refresh tokens.
   *
   * @return false|array
   *   Tokens or false.
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function refreshTokens(): false|array {
    $session = $this->requestStack->getCurrentRequest()->getSession();
    $refresh_token = $session->get('openid_connect_refresh_token');

    $plugin_id = $this->requestStack->getCurrentRequest()
      ->getSession()
      ->get('openid_connect_plugin_id');

    $storage = $this->entityManager->getStorage('openid_connect_client');
    $entities = $storage->loadByProperties([
      'plugin' => 'tunnistamo',
      'id' => $plugin_id,
    ]);

    if (!isset($entities[$plugin_id])) {
      return FALSE;
    }

    /** @var \Drupal\helfi_tunnistamo\Plugin\OpenIDConnectClient\Tunnistamo $client */
    $client = $entities[$plugin_id];
    $configuration = $client->getPlugin()->getConfiguration();

    // Exchange a refresh token for new tokens.
    $endpoints = $this->getOpenIdConfiguration();
    $request_options = [
      'form_params' => [
        'refresh_token' => $refresh_token,
        'client_id' => $configuration['client_id'],
        'client_secret' => $configuration['client_secret'],
        'grant_type' => 'refresh_token',
      ],
      'headers' => [
        'Accept' => 'application/json',
      ],
    ];

    try {
      $response = $this->httpClient->request('POST', $endpoints['token_endpoint'], $request_options);
      $this->dispatchOperationEvent('TOKEN FETCH');
      $response_data = json_decode((string) $response->getBody(), TRUE);
      // Expected result.
      $tokens = [
        'id_token' => $response_data['id_token'] ?? NULL,
        'access_token' => $response_data['access_token'] ?? NULL,
      ];

      $this->openidConnectSession->saveIdToken($tokens['id_token']);
      $this->openidConnectSession->saveAccessToken($tokens['access_token']);

      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = REQUEST_TIME + $response_data['expires_in'];
        $session->set('openid_connect_expire', $tokens['expire']);
      }
      if (array_key_exists('refresh_token', $response_data)) {
        $tokens['refresh_token'] = $response_data['refresh_token'];
        $session->set('openid_connect_refresh_token', $response_data['refresh_token']);
      }
      return $tokens;
    }
    catch (\Exception $e) {
      $this->dispatchExceptionEvent($e);
      $variables = [
        '@message' => 'Could not refresh tokens',
        '@error_message' => $e->getMessage(),
      ];
      $this->logger->error(
        '@message: @error_message',
        $variables
      );
      return FALSE;
    }
  }

  /**
   * Verify JWT token.
   *
   * @param string $jwt
   *   JWT token.
   *
   * @return array
   *   Is token valid or not.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function verifyJwtToken(string $jwt): array {
    $jwks = $this->getJwks();

    $this->debugPrint('JWKS -> @jwks', ['@jwks' => Json::encode($jwks)]);

    return (array) JWT::decode($jwt, JWK::parseKeySet($this->getJwks()));
  }

  /**
   * Print debug messages.
   *
   * @param string $message
   *   Message.
   * @param array $replacements
   *   Replacements.
   */
  public function debugPrint(string $message, array $replacements = []): void {
    if ($this->isDebug()) {
      $this->logger->debug($message, $replacements);
    }
  }

  /**
   * Is debug on?
   *
   * @return bool
   *   Debug boolean.
   */
  public function isDebug(): bool {
    return $this->debug;
  }

  /**
   * Set debug value.
   *
   * @param bool $debug
   *   Debug boolean value.
   */
  public function setDebug(bool $debug): void {
    $this->debug = $debug;
  }

  /**
   * Get api endpoint for apikeys.
   *
   * @return string
   *   Endpoint url
   */
  public function getApiTokenEndpoint(): string {
    return $this->apiTokenEndpoint;
  }

  /**
   * Set api endpoint.
   *
   * @param string $apiTokenEndpoint
   *   Endpoint url.
   */
  public function setApiTokenEndpoint(string $apiTokenEndpoint): void {
    $this->apiTokenEndpoint = $apiTokenEndpoint;
  }

  /**
   * Dispatches exception event.
   *
   * @param \Exception $exception
   *   The exception.
   */
  private function dispatchExceptionEvent(\Exception $exception): void {
    $event = new HelsinkiProfiiliExceptionEvent($exception);
    $this->eventDispatcher->dispatch($event, HelsinkiProfiiliExceptionEvent::EVENT_ID);
  }

  /**
   * Dispatches exception event.
   *
   * @param string $message
   *   The message.
   */
  private function dispatchOperationEvent(string $message): void {
    $event = new HelsinkiProfiiliOperationEvent($message);
    $this->eventDispatcher->dispatch($event, HelsinkiProfiiliOperationEvent::EVENT_ID);
  }

  /**
   * Get tunnistamo env url from env variable.
   *
   * @return string
   *   The url or false.
   */
  public function getTunnistamoEnvUrl(): string {
    return getenv('TUNNISTAMO_ENVIRONMENT_URL');
  }

}
