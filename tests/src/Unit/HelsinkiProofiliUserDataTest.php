<?php

declare(strict_types=1);

namespace Drupal\tests\helfi_helsinki_profiili\Unit;

use Drupal\Component\Serialization\Json;
use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\helfi_helsinki_profiili\HelsinkiProfiiliUserData;
use Drupal\openid_connect\OpenIDConnectSession;
use Drupal\Tests\UnitTestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use GuzzleHttp\ClientInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Http\RequestStack;
use Drupal\helfi_api_base\Environment\EnvironmentResolverInterface;

/**
 * Tests HelsinkiProfiiliUserData class.
 *
 * @coversDefaultClass \Drupal\helfi_helsinki_profiile\HelsinkiProfiiliUserData
 * @group helfi_helsinki_profiili
 */
class HelsinkiProofiliUserDataTest extends UnitTestCase {

  use ProphecyTrait;

  /**
   * Service instance.
   *
   * @var \Drupal\helfi_helsinki_profiili\HelsinkiProfiiliUserData
   */
  protected $service;

  /**
   * {@inheritdoc}
   */
  public function setUp():void {
    $container = new ContainerBuilder();
    \Drupal::setContainer($container);

    $container->set('openid_connect.session', $this->prophesize(OpenIDConnectSession::class)->reveal());
    $container->set('http_client', $this->prophesize(ClientInterface::class)->reveal());
    $container->set('logger.factory', $this->prophesize(LoggerChannelFactoryInterface::class)->reveal());
    $container->set('current_user', $this->prophesize(AccountProxyInterface::class)->reveal());
    $container->set('request_stack', $this->prophesize(RequestStack::class)->reveal());
    $container->set('helfi_api_base.environment_resolver', $this->prophesize(EnvironmentResolverInterface::class)->reveal());

    $configFactory = $this->getConfigFactoryStub([
      'helfi_helsinki_profiili.settings' => ['roles' => []],
    ]);

    $container->set('config.factory', $configFactory);

    $service = new HelsinkiProfiiliUserData(
      $this->prophesize(OpenIDConnectSession::class)->reveal(),
      $this->prophesize(ClientInterface::class)->reveal(),
      $this->prophesize(LoggerChannelFactoryInterface::class)->reveal(),
      $this->prophesize(AccountProxyInterface::class)->reveal(),
      $this->prophesize(RequestStack::class)->reveal(),
      $this->prophesize(EnvironmentResolverInterface::class)->reveal(),
    );

    $this->service = $service;
  }

  /**
   * Loads fixture json and returns it.
   *
   * @param string $file
   *   Fila name.
   *
   * @return array
   *   JSON decoded array.
   */
  private function getFixture($file) {
    $handle = fopen(__DIR__ . '/../../../fixtures/' . $file, 'r');
    $content = fread($handle, filesize(__DIR__ . '/../../../fixtures/' . $file));
    return JSON::decode($content);
  }

  /**
   * Tests that function return first primary node.
   *
   * @covers ::checkPrimaryFields
   */
  public function testGetsFirstPrimaryNode() {
    $json = $this->getFixture('multiple_primaries.json');
    $data = $this->service->checkPrimaryFields($json);

    $this->assertEquals($data['myProfile']['primaryEmail']['email'], 'primary@test.test');
    $this->assertEquals($data['myProfile']['primaryPhone']['phone'], '+358111111111');
  }

  /**
   * Tests that function returns first node.
   *
   * Incase no primary nodes are available.
   *
   * @covers ::checkPrimaryFields
   */
  public function testGetsFirstNodeWhenNoPrimary() {
    $json = $this->getFixture('profile_data.json');
    $data = $this->service->checkPrimaryFields($json);

    $this->assertEquals($data['myProfile']['primaryEmail']['email'], 'primary@test.test');
  }

  /**
   * Tests that function doesn't change primaryFields.
   *
   * If there is non-null value already.
   *
   * @covers ::checkPrimaryFields
   */
  public function testDoesntChangeValidPrimaryData() {
    $json = $this->getFixture('profile_data_valid_primary.json');
    $data = $this->service->checkPrimaryFields($json);

    $this->assertEquals($data['myProfile']['primaryEmail']['email'], 'primary@test.test');
    $this->assertEquals($data['myProfile']['primaryPhone']['phone'], '+358000000000');
  }

  /**
   * Tests that data is filtered through XSS::filter.
   *
   * @covers ::filterData
   */
  public function testXssFiltering() {
    $json = $this->getFixture('xss.json');
    $filteredData = $this->service->filterData($json);

    $this->assertEquals(
      $filteredData['myProfile']['verifiedPersonalInformation']['firstName'],
      'Nordea alert(1)'
    );
  }

}
