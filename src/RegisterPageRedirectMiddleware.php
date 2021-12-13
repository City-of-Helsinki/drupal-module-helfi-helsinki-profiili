<?php

namespace Drupal\helfi_helsinki_profiili;

use Drupal\Core\Messenger\Messenger;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * RegisterPageRedirectMiddleware middleware.
 */
class RegisterPageRedirectMiddleware implements HttpKernelInterface {

  use StringTranslationTrait;

  /**
   * The kernel.
   *
   * @var \Symfony\Component\HttpKernel\HttpKernelInterface
   */
  protected $httpKernel;

  protected Messenger $messenger;

  /**
   * Constructs the RegisterPageRedirectMiddleware object.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $http_kernel
   *   The decorated kernel.
   */
  public function __construct(HttpKernelInterface $http_kernel, Messenger $messenger) {
    $this->httpKernel = $http_kernel;
    $this->messenger = $messenger;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = TRUE) {

    $url = $request->getRequestUri();
    $language = \Drupal::languageManager()->getCurrentLanguage()->getId();

    if (
      str_contains($url, 'user/register') ||
      str_contains($url, 'user/password')
    ) {
      return new RedirectResponse('/' . $language);
    }

    return $this->httpKernel->handle($request, $type, $catch);
  }

}
