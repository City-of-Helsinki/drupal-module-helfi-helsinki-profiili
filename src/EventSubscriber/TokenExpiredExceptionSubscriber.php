<?php

namespace Drupal\helfi_helsinki_profiili\EventSubscriber;

use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Url;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Helsinki-profiili event subscriber.
 */
class TokenExpiredExceptionSubscriber implements EventSubscriberInterface {

  /**
   * The messenger.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * Constructs event subscriber.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger.
   */
  public function __construct(MessengerInterface $messenger) {
    $this->messenger = $messenger;
  }

  /**
   * Kernel request event handler.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   Response event.
   */
  public function onKernelException(ExceptionEvent $event) {
    $exception = $event->getThrowable();
    if (get_class($exception) == 'Drupal\helfi_helsinki_profiili\TokenExpiredException') {
      user_logout();
      $this->messenger->addError('Session timeout, please relogin');
      $url = Url::fromRoute('<front>');
      $response = new RedirectResponse($url->toString());
      $event->setResponse($response);
    }
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    return [
      KernelEvents::EXCEPTION => ['onKernelException'],
    ];
  }

}
