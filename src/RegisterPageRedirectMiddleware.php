<?php

namespace Drupal\helfi_helsinki_profiili;

use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Messenger\Messenger;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Prevent access to user/register & user/password urls and redirect.
 */
class RegisterPageRedirectMiddleware implements HttpKernelInterface {

  use StringTranslationTrait;

  /**
   * The kernel.
   *
   * @var \Symfony\Component\HttpKernel\HttpKernelInterface
   */
  protected HttpKernelInterface $httpKernel;

  /**
   * Show messages to users.
   *
   * @var \Drupal\Core\Messenger\Messenger
   */
  protected Messenger $messenger;

  /**
   * Translate things.
   *
   * @var \Drupal\Core\Language\LanguageManagerInterface
   */
  protected LanguageManagerInterface $languageManager;

  /**
   * Constructs the RegisterPageRedirectMiddleware object.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $http_kernel
   *   The decorated kernel.
   * @param \Drupal\Core\Messenger\Messenger $messenger
   *   Messenger service.
   * @param \Drupal\Core\Language\LanguageManagerInterface $languageManager
   *   Language Manager service.
   */
  public function __construct(HttpKernelInterface $http_kernel, Messenger $messenger, LanguageManagerInterface $languageManager) {
    $this->httpKernel = $http_kernel;
    $this->messenger = $messenger;
    $this->languageManager = $languageManager;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = TRUE): RedirectResponse|Response {

    $url = $request->getRequestUri();
    $language = $this->languageManager->getCurrentLanguage()->getId();

    if (
      str_contains($url, 'user/register') ||
      str_contains($url, 'user/password')
    ) {
      return new RedirectResponse('/' . $language);
    }

    return $this->httpKernel->handle($request, $type, $catch);
  }

}
