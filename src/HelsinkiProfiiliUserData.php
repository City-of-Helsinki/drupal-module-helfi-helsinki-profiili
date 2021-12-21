<?php

namespace Drupal\helfi_helsinki_profiili;

use Drupal\Component\Serialization\Json;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\openid_connect\OpenIDConnectSession;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
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
   */
  public function __construct(
    OpenIDConnectSession $openid_connect_session,
    ClientInterface $http_client,
    LoggerChannelFactoryInterface $logger_factory,
    AccountProxyInterface $currentUser) {

    $this->openidConnectSession = $openid_connect_session;
    $this->httpClient = $http_client;

    $this->logger = $logger_factory->get('helsinki_profiili');
    $this->currentUser = $currentUser;

    if ($this->isAuthenticatedExternally()) {
      $this->userProfileData = $this->getUserProfileData();
    }
    else {
      $this->userProfileData = [];
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
   * Get user profile data from tunnistamo.
   *
   * @return array
   *   User profile data.
   *
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function getUserProfileData(): array {

    if (!empty($this->userProfileData)) {
      return $this->userProfileData;
    }

    $endpoint = getenv('USERINFO_ENDPOINT');
    $query = $this->graphqlQuery();
    $variables = [];
    $token = $this->openidConnectSession->retrieveIdToken();

    $headers = [
      'Content-Type: application/json',
      'User-Agent: Avustus2 dev application',
    ];
    if (NULL !== $token) {
      $headers[] = "Authorization: bearer $token";
    }

    try {
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

      // @todo fix graphql error reporting
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
      }
      else {
        $this->logger->notice('User %user got their HelsinkiProfiili data form endpoint', [
          '%user' => $this->currentUser->getDisplayName(),
        ]);
      }

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

    // @todo remove hardcoded myprofile data
    $data = $this->demoData();

    return Json::decode($data);
  }

  /**
   * Get SSN from data structure.
   *
   * @return mixed
   *   User SSN.
   */
  public function getSsn() {
    return $this->userProfileData["myProfile"]["verifiedPersonalInformation"]["nationalIdentificationNumber"];
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
