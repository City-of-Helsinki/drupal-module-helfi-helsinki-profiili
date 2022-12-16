<?php

namespace Drupal\helfi_helsinki_profiili;

use Drupal\Component\Serialization\Json;
use Drupal\Component\Utility\Xss;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\TempStore\PrivateTempStore;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\TempStore\TempStoreException;
use Drupal\helfi_api_base\Environment\EnvironmentResolverInterface;
use Drupal\openid_connect\OpenIDConnectSession;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use Okta\JwtVerifier\Adaptors\FirebasePhpJwt;
use Okta\JwtVerifier\Discovery\Oidc;
use Okta\JwtVerifier\JwtVerifierBuilder;

/**
 * Integrate HelsinkiProfiili data to Drupal User.
 */
class HelsinkiProfiiliUserData {


  public const TESTING_ENVIRONMENT = 'https://tunnistamo.test.hel.ninja';

  public const STAGING_ENVIRONMENT = 'https://api.hel.fi/sso-test';

  public const PRODUCTION_ENVIRONMENT = 'https://api.hel.fi/sso';

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
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $logger;

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
   * Access to session storage.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStore
   */
  protected PrivateTempStore $tempStore;

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
   * Store details about oidc issuer.
   *
   * @var array
   */
  private array $openIdConfiguration;

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
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $tempstore
   *   Access session store.
   *
   * @throws \Drupal\helfi_helsinki_profiili\ProfileDataException
   */
  public function __construct(
    OpenIDConnectSession          $openid_connect_session,
    ClientInterface               $http_client,
    LoggerChannelFactoryInterface $logger_factory,
    AccountProxyInterface         $currentUser,
    PrivateTempStoreFactory       $tempstore,
    EnvironmentResolverInterface  $environmentResolver) {

    $this->openidConnectSession = $openid_connect_session;
    $this->httpClient = $http_client;
    $this->environmentResolver = $environmentResolver;

    $this->logger = $logger_factory->get('helsinki_profiili');
    $this->currentUser = $currentUser;
    $this->tempStore = $tempstore->get('helsinki_profiili');

    $this->openIdConfiguration = [];

    $config = \Drupal::config('helfi_helsinki_profiili.settings');
    $rolesConfig = $config->get('roles');

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
   * @var array $userData
   *  Userdata retrieved from HP.
   *
   * @throws \Drupal\Core\TempStore\TempStoreException
   */
  public function setUserData($userData) {
    return $this->setToCache('userData', $userData);
  }

  /**
   * Get user data from tempstore.
   *
   * @return array
   *   Userdata from tempstore.
   */
  public function getUserData() {
    if ($this->isCached('userData')) {
      return $this->getFromCache('userData');
    }
    else {
      return NULL;
    }
  }

  /**
   * Get access tokens from helsinki profiili.
   *
   * @return array|null
   *   Accesstokens or null.
   *
   * @throws \Drupal\helfi_helsinki_profiili\TokenExpiredException
   */
  public function getApiAccessTokens() {
    // Access token to get api access tokens in next step.
    $accessToken = $this->openidConnectSession->retrieveAccessToken();

    if ($accessToken == NULL) {
      return NULL;
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

    if ($refetch == FALSE && $this->isCached('myProfile')) {
      $myProfile = $this->getFromCache('myProfile');
      return $myProfile;
    }

    // End point to access profile data.
    $endpoint = getenv('USERINFO_PROFILE_ENDPOINT');
    // Get query.
    $query = $this->graphqlQuery();
    $variables = [];

    try {

      // Use access token to fetch profiili token from token service.
      $apiAccessToken = $this->getHelsinkiProfiiliToken($accessToken);

      $headers = [
        'Content-Type' => 'application/json',
      ];
      // Use api access token if set, if not, return NULL.
      if (isset($apiAccessToken['https://api.hel.fi/auth/helsinkiprofile'])) {
        $headers['Authorization'] = 'Bearer ' . $apiAccessToken['https://api.hel.fi/auth/helsinkiprofile'];
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
          'variables' => $variables,
        ],
      ]);

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
      // Make sure that data coming from HP is sanitized and does not contain
      // anything worth removing.
      $cleaned = array_walk_recursive(
        $data,
        function (&$item) {
          if (is_string($item)) {
            $item = Xss::filter($item);
          }
        }
      );

      // Set profile data to cache so that no need to fetch more data.
      $this->setToCache('myProfile', $data);
      return $data;

    } catch (ClientException|ServerException $e) {

      $this->logger->error(
        '/userinfo endpoint threw errorcode %ecode: @error',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
      );

      return NULL;

    } catch (TempStoreException $e) {
      $this->logger->error(
        'Caching userprofile data failed',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
      );
    } catch (GuzzleException $e) {
    } catch (ProfileDataException $e) {
      $this->logger->error(
        $e->getMessage()
      );

      return NULL;

    }

    return NULL;
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
      $response = $this->httpClient->request('GET', 'https://tunnistamo.test.hel.ninja/api-tokens/', [
        'headers' => [
          'Authorization' => 'Bearer ' . $accessToken,
        ],
      ]);
      $body = $response->getBody()->getContents();

      if (strlen($body) < 5) {
        throw new ProfileDataException('No data from profile endpoint');
      }
      return Json::decode($body);
    } catch (ProfileDataException $profileDataException) {
      $this->logger->error('Trying to get tokens from api-tokens endpoint, got empty body: @error', ['@error' => $profileDataException->getMessage()]);
      return NULL;
    } catch (GuzzleException|\Exception $e) {
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
  private function isCached(string $key): bool {
    $tempStoreData = $this->tempStore->get('helsinki_profiili');
    return isset($tempStoreData[$key]) && !empty($tempStoreData[$key]);
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
      if ($key == '') {
        if (method_exists($this->tempStore, 'deleteAllUser')) {
          $this->tempStore->deleteAllUser();
        }
      }
      else {
        $this->tempStore->delete($key);
      }

      return TRUE;
    } catch (\Exception $e) {
      return FALSE;
    }
  }

  /**
   * Get item from cache.
   *
   * @param string $key
   *   Key to fetch from tempstore.
   *
   * @return mixed|null
   *   Data in cache or null
   */
  private function getFromCache(string $key) {
    $tempStoreData = $this->tempStore->get('helsinki_profiili');
    return (isset($tempStoreData[$key]) && !empty($tempStoreData[$key])) ? $tempStoreData[$key] : NULL;
  }

  /**
   * Add item to cache.
   *
   * @param string $key
   *   Used key for caching.
   * @param array $data
   *   Cached data.
   *
   * @throws \Drupal\Core\TempStore\TempStoreException
   */
  private function setToCache(string $key, array $data) {
    $tempStoreData = $this->tempStore->get('helsinki_profiili');
    $tempStoreData[$key] = $data;
    $this->tempStore->set('helsinki_profiili', $tempStoreData);
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
   * @param array $openIdConfiguration
   */
  public function setOpenIdConfiguration(array $openIdConfiguration): void {
    $this->openIdConfiguration = $openIdConfiguration;
  }

  /**
   * Get openid configurations.
   *
   * @return array
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
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function getOpenidConfigurationFromIssuer(): array {
    $endpointMap = [
      'local' => self::TESTING_ENVIRONMENT,
      'dev' => self::TESTING_ENVIRONMENT,
      'test' => self::TESTING_ENVIRONMENT,
      'stage' => self::STAGING_ENVIRONMENT,
      'prod' => self::PRODUCTION_ENVIRONMENT,
    ];
    $base = self::STAGING_ENVIRONMENT;

    try {
      // Attempt to automatically detect endpoint.
      $env = $this->environmentResolver->getActiveEnvironmentName();

      if (isset($endpointMap[$env])) {
        $base = $endpointMap[$env];
      }
    } catch (\InvalidArgumentException) {
    }

    return Json::decode(
      $this->httpClient->request(
        'GET',
        sprintf('%s/openid/.well-known/openid-configuration/', $base)
      )->getBody()
    );
  }

  public function getJwks() {
    $data = [];
    $config = $this->getOpenIdConfiguration();

    $response = $this->httpClient->request(
      'GET',
      $config["jwks_uri"]
    );

    return Json::decode($response->getBody()->getContents());

  }

  /**
   * @param $tokenString
   *
   * @return mixed
   */
  public function verifyJwtToken($tokenString) {

//    $tokenData = $this->parseToken($tokenString);
//
//    $openIdConfig = $this->getOpenIdConfiguration();
//    $jwksConfig = $this->getJwks();
//
//    $this->is_jwt_valid($tokenString,$jwksConfig);

//    $jwtVerifier = (new JwtVerifierBuilder())
//      ->setDiscovery(new Oidc()) // This is not needed if using oauth.  The other option is `new \Okta\JwtVerifier\Discovery\OIDC`
//      ->setAdaptor(new FirebasePhpJwt())
//      ->setAudience($tokenData["aud"])
//      ->setClientId($jwksConfig)
//      ->setIssuer($openIdConfig["issuer"])
//      ->build();
//
//    $t = $jwtVerifier->verify($tokenString);

    return 'asdf';
  }

function base64url_encode($data) {
return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

  function is_jwt_valid($jwt, $secret ) {
    // split the jwt
    $tokenParts = explode('.', $jwt);
    $header = base64_decode($tokenParts[0]);
    $payload = base64_decode($tokenParts[1]);
    $signature_provided = $tokenParts[2];

    // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
    $expiration = json_decode($payload)->exp;
    $is_token_expired = ($expiration - time()) < 0;

    // build a signature based on the header and payload using the secret
    $base64_url_header = $this->base64url_encode($header);
    $base64_url_payload = $this->base64url_encode($payload);
    $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret["keys"][0]["n"], true);
    $base64_url_signature = $this->base64url_encode($signature);

    // verify it matches the signature provided in the jwt
    $is_signature_valid = ($base64_url_signature === $signature_provided);

    if ($is_token_expired || !$is_signature_valid) {
      return FALSE;
    } else {
      return TRUE;
    }
  }

}
