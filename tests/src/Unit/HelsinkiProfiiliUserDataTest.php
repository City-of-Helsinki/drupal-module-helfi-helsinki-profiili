<?php

declare(strict_types=1);

namespace Drupal\Tests\helfi_helsinki_profiili\Unit;

use Drupal\Component\EventDispatcher\ContainerAwareEventDispatcher;
use Drupal\Component\Serialization\Json;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactory;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\helfi_api_base\Environment\EnvironmentResolverInterface;
use Drupal\helfi_helsinki_profiili\HelsinkiProfiiliUserData;
use Drupal\openid_connect\OpenIDConnectSession;
use Drupal\Tests\UnitTestCase;
use GuzzleHttp\ClientInterface;
use Prophecy\PhpUnit\ProphecyTrait;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Tests HelsinkiProfiiliUserData class.
 *
 * @coversDefaultClass \Drupal\helfi_helsinki_profiile\HelsinkiProfiiliUserData
 * @group helfi_helsinki_profiili
 */
class HelsinkiProfiiliUserDataTest extends UnitTestCase {

  use ProphecyTrait;

  /**
   * Helper method to return fresh instance of HelsinkiProfiiliUserData.
   */
  public function getService(): HelsinkiProfiiliUserData {

    $configFactory = $this->getConfigFactoryStub([
      'helfi_helsinki_profiili.settings' => ['roles' => []],
    ]);
    $loggerFactoryProphecy = $this->prophesize(LoggerChannelFactory::class);
    $loggerFactoryProphecy->get('helsinki_profiili')->willReturn($this->prophesize(LoggerChannelInterface::class));
    $service = new HelsinkiProfiiliUserData(
      $this->prophesize(OpenIDConnectSession::class)->reveal(),
      $this->prophesize(ClientInterface::class)->reveal(),
      $loggerFactoryProphecy->reveal(),
      $this->prophesize(AccountProxyInterface::class)->reveal(),
      $this->prophesize(RequestStack::class)->reveal(),
      $this->prophesize(EnvironmentResolverInterface::class)->reveal(),
      $this->prophesize(EntityTypeManagerInterface::class)->reveal(),
      $this->prophesize(ContainerAwareEventDispatcher::class)->reveal(),
      $configFactory,
    );
    return $service;
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
   */
  public function testGetsFirstPrimaryNode() {
    $json = $this->getFixture('multiple_primaries.json');
    $service = $this->getService();
    $data = $service->checkPrimaryFields($json);

    $this->assertEquals($data['myProfile']['primaryEmail']['email'], 'primary@test.test');
    $this->assertEquals($data['myProfile']['primaryPhone']['phone'], '+358111111111');
  }

  /**
   * Tests that function returns first node.
   *
   * Incase no primary nodes are available.
   */
  public function testGetsFirstNodeWhenNoPrimary() {
    $json = $this->getFixture('profile_data.json');
    $service = $this->getService();
    $data = $service->checkPrimaryFields($json);

    $this->assertEquals($data['myProfile']['primaryEmail']['email'], 'primary@test.test');
  }

  /**
   * Tests that function doesn't change primaryFields.
   *
   * If there is non-null value already.
   */
  public function testDoesntChangeValidPrimaryData() {
    $json = $this->getFixture('profile_data_valid_primary.json');
    $service = $this->getService();
    $data = $service->checkPrimaryFields($json);

    $this->assertEquals($data['myProfile']['primaryEmail']['email'], 'primary@test.test');
    $this->assertEquals($data['myProfile']['primaryPhone']['phone'], '+358000000000');
  }

  /**
   * Tests that data is filtered through XSS::filter.
   */
  public function testXssFiltering() {
    $json = $this->getFixture('xss.json');
    $service = $this->getService();
    $filteredData = $service->filterData($json);

    $this->assertEquals(
      $filteredData['myProfile']['verifiedPersonalInformation']['firstName'],
      'Nordea alert(1)'
    );
  }

}
