<?php

namespace Drupal\helfi_helsinki_profiili;

use Drupal\Component\Serialization\Json;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\TempStore\PrivateTempStore;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\TempStore\TempStoreException;
use Drupal\openid_connect\OpenIDConnectSession;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;

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
   */
  public function __construct(
    OpenIDConnectSession $openid_connect_session,
    ClientInterface $http_client,
    LoggerChannelFactoryInterface $logger_factory,
    AccountProxyInterface $currentUser,
    PrivateTempStoreFactory $tempstore) {

    $this->openidConnectSession = $openid_connect_session;
    $this->httpClient = $http_client;

    $this->logger = $logger_factory->get('helsinki_profiili');
    $this->currentUser = $currentUser;
    $this->tempStore = $tempstore->get('helsinki_profiili');
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
   * Get user profile data from tunnistamo.
   *
   * @return array
   *   User profile data.
   */
  public function getUserProfileData(): ?array {

    if ($this->isCached('myProfile')) {
      return $this->getFromCache('myProfile');
    }

    // End point to access profile data.
    $endpoint = getenv('USERINFO_PROFILE_ENDPOINT');
    // Get query.
    $query = $this->graphqlQuery();
    $variables = [];
    // Access token to get api access tokens in next step.
    $accessToken = $this->openidConnectSession->retrieveAccessToken();
    // Use access token to fetch profiili token from token service.
    $apiAccessToken = $this->getHelsinkiProfiiliToken($accessToken);

    $headers = [
      'Content-Type' => 'application/json',
    ];
    // Use api access token if set, if not, return NULL.
    if (isset($apiAccessToken['https://api.hel.fi/auth/helsinkiprofile'])) {
      $headers["Authorization"] = "Bearer " . $apiAccessToken['https://api.hel.fi/auth/helsinkiprofile'];
    }
    else {
      // No point going further if no token is received.
      return NULL;
    }

    try {
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
        return NULL;
      }
      else {
        $this->logger->notice('User %user got their HelsinkiProfiili data form endpoint', [
          '%user' => $this->currentUser->getDisplayName(),
        ]);
      }
      // Set profile data to cache so that no need to fetch more data.
      $this->setToCache('profile_data', $data);
      return $data;

    }
    catch (ClientException | ServerException $e) {
      $this->logger->error(
        '/userinfo endpoint threw errorcode %ecode: @error',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
          );
    }
    catch (TempStoreException $e) {
      $this->logger->error(
        'Caching userprofile data failed',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
          );
    }
    catch (GuzzleException $e) {
    }

    return NULL;
  }

  /**
   * Fetch proper tokens from api-tokens endopoint.
   *
   * @param string $accessToken
   *   Token from authorization service.
   *
   * @return array
   *   Token data
   */
  private function getHelsinkiProfiiliToken(string $accessToken): ?array {
    try {
      $response = $this->httpClient->request('GET', 'https://tunnistamo.test.hel.ninja/api-tokens/', [
        'headers' => [
          "Authorization" => "Bearer " . $accessToken,
        ],
      ]);
      return Json::decode($response->getBody()->getContents());
    }
    catch (GuzzleException | \Exception $e) {
      $this->logger->error(
        'Error retrieving access token %ecode: @error',
        [
          '%ecode' => $e->getCode(),
          '@error' => $e->getMessage(),
        ]
          );
    }

    return NULL;

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
   * @return array|string
   *   The parsed JWT token or the original string.
   */
  protected function parseToken(string $token) {
    $parts = explode('.', $token, 3);
    if (count($parts) === 3) {
      $decoded = Json::decode(base64_decode($parts[1]));
      if (is_array($decoded)) {
        return $decoded;
      }
    }
    return $token;
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
    $this->tempStore->set('helsinki_profiili', $data);
  }

  /**
   * Demo data for when the strong auth is broken.
   *
   * @return string
   *   Profile data demo.
   */
  private function demoData(): string {

    $this->logger->error(
      'USERINFO USING DEMO DATA for %user',
      [
        '%user' => $this->currentUser->getDisplayName(),
      ]
    );

    return '{
      "myProfile": {
          "id": "UHJvZmlsZU5vZGU6NzdhMjdhZmItMzQyNi00YTMyLTk0YjEtNzY5MWNiNjAxYmU5",
          "firstName": "Mika",
          "lastName": "Hietanen",
          "nickname": "",
          "language": "FINNISH",
          "primaryAddress": {
              "id": "QWRkcmVzc05vZGU6NzYxNg==",
              "primary": true,
              "address": "Vuorimiehenkatu 35",
              "postalCode": "00100",
              "city": "Helsinki",
              "countryCode": "FI",
              "addressType": "OTHER",
              "__typename": "AddressNode"
          },
          "addresses": {
              "edges": [
                  {
                      "node": {
                          "primary": false,
                          "id": "QWRkcmVzc05vZGU6NzYxOQ==",
                          "address": "Mannerheimintie 37",
                          "postalCode": "00250",
                          "city": "Helsinki",
                          "countryCode": "FI",
                          "addressType": "OTHER",
                          "__typename": "AddressNode"
                      },
                      "__typename": "AddressNodeEdge"
                  },
                  {
                      "node": {
                          "primary": true,
                          "id": "QWRkcmVzc05vZGU6NzYxNg==",
                          "address": "Vuorimiehenkatu 35",
                          "postalCode": "00100",
                          "city": "Helsinki",
                          "countryCode": "FI",
                          "addressType": "OTHER",
                          "__typename": "AddressNode"
                      },
                      "__typename": "AddressNodeEdge"
                  }
              ],
              "__typename": "AddressNodeConnection"
          },
          "primaryEmail": {
              "id": "RW1haWxOb2RlOjgwNDQ=",
              "email": "aman.yadav@anders.fi",
              "primary": true,
              "emailType": "NONE",
              "__typename": "EmailNode"
          },
          "emails": {
              "edges": [
                  {
                      "node": {
                          "primary": true,
                          "id": "RW1haWxOb2RlOjgwNDQ=",
                          "email": "aman.yadav@anders.fi",
                          "emailType": "NONE",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwNDI=",
                          "email": "test@test.fi",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwNDA=",
                          "email": "test@test.fi",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwMzk=",
                          "email": "asdf@testi.com",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwMzg=",
                          "email": "nizar.rahme@digia.com",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwMzc=",
                          "email": "nizar.rahme@digia.com",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwNDE=",
                          "email": "mika.hietanen@anders.fi",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  },
                  {
                      "node": {
                          "primary": false,
                          "id": "RW1haWxOb2RlOjgwMzY=",
                          "email": "test@test.com",
                          "emailType": "OTHER",
                          "__typename": "EmailNode"
                      },
                      "__typename": "EmailNodeEdge"
                  }
              ],
              "__typename": "EmailNodeConnection"
          },
          "primaryPhone": {
              "id": "UGhvbmVOb2RlOjgxNzE=",
              "phone": "+358500555333",
              "primary": true,
              "phoneType": "OTHER",
              "__typename": "PhoneNode"
          },
          "phones": {
              "edges": [
                  {
                      "node": {
                          "primary": true,
                          "id": "UGhvbmVOb2RlOjgxNzE=",
                          "phone": "+358500555333",
                          "phoneType": "OTHER",
                          "__typename": "PhoneNode"
                      },
                      "__typename": "PhoneNodeEdge"
                  }
              ],
              "__typename": "PhoneNodeConnection"
          },
          "verifiedPersonalInformation": {
              "firstName": "Nordea",
              "lastName": "Demo",
              "givenName": "Nordea",
              "nationalIdentificationNumber": "210281-9988",
              "municipalityOfResidence": "Turku",
              "municipalityOfResidenceNumber": "853",
              "permanentAddress": {
                  "streetAddress": "Mansikkatie 11",
                  "postalCode": "20006",
                  "postOffice": "TURKU",
                  "__typename": "VerifiedPersonalInformationAddressNode"
              },
              "temporaryAddress": null,
              "permanentForeignAddress": null,
              "__typename": "VerifiedPersonalInformationNode"
          },
          "__typename": "ProfileNode"
      }
    }';
  }

}
