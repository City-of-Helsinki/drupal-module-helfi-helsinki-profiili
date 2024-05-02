<?php

namespace Drupal\helfi_helsinki_profiili_audit_logging\EventSubscriber;

use Drupal\helfi_audit_log\AuditLogService;
use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent;
use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliOperationEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Monitors submission view events and logs them to audit log.
 */
class HelsinkiProfiiliEventSubscriber implements EventSubscriberInterface {

  /**
   * {@inheritdoc}
   */
  public function __construct(
    private readonly AuditLogService $auditLogService,
  ) {

  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[HelsinkiProfiiliExceptionEvent::EVENT_ID][] = ['onException'];
    $events[HelsinkiProfiiliOperationEvent::EVENT_ID][] = ['onOperation'];
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

  /**
   * Audit log the operation.
   *
   * @param \Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliOperationEvent $event
   *   An exception event.
   */
  public function onOperation(HelsinkiProfiiliOperationEvent $event) {
    $name = $event->getName();
    $message = [
      'operation' => 'HELSINKI_PROFIILI_QUERY',
      'status' => 'SUCCESS',
      'target' => [
        'name' => $name,
        'type' => $name,
      ],
    ];

    $this->auditLogService->dispatchEvent($message);
  }

}
