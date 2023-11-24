<?php

namespace Drupal\helfi_helsinki_profiili_audit_logging\EventSubscriber;

use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent;
use Drupal\helfi_audit_log\AuditLogService;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Monitors submission view events and logs them to audit log.
 */
class HelsinkiProfiiliExceptionEventSubscriber implements EventSubscriberInterface {

  /**
   * {@inheritdoc}
   */
  public function __construct(
    private AuditLogService $auditLogService
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[HelsinkiProfiiliExceptionEvent::EVENT_ID][] = ['onException'];
    return $events;
  }

  /**
   * Audit log the exception.
   *
   * @param \Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent $event
   *   An exception event.
   */
  public function onException(HelsinkiProfiiliExceptionEvent $event) {
    $exception = $event->getException();
    $message = [
      'operation' => 'HELSINKI_PROFIILI_QUERY',
      'status' => 'EXCEPTION',
      'target' => [
        'name' => $exception->getMessage(),
        'type' => get_class($exception),
      ],
    ];

    $this->auditLogService->dispatchEvent($message);
  }

}
