<?php

namespace Drupal\helfi_helsinki_profiili\EventSubscriber;

use Drupal\Core\Messenger\MessengerInterface;
use Drupal\helfi_audit_log\AuditLogService;
use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Monitors submission view events and logs them to audit log.
 */
class HelsinkiProfiiliExceptionEventSubscriber implements EventSubscriberInterface {

  /**
   * The messenger.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected MessengerInterface $messenger;

  /**
   * Audit logger.
   *
   * @var \Drupal\helfi_audit_log\AuditLogService
   */
  protected AuditLogService $auditLogService;

  /**
   * Constructs event subscriber.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger.
   * @param \Drupal\helfi_audit_log\AuditLogService $auditLogService
   *   Audit log mandate errors.
   */
  public function __construct(
    MessengerInterface $messenger,
    AuditLogService $auditLogService,
  ) {
    $this->messenger = $messenger;
    $this->auditLogService = $auditLogService;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    $events[HelsinkiProfiiliExceptionEvent::EVENT_ID][] = ['onException'];
    return $events;
  }

  /**
   * Audit log the exception.
   *
   * @param \Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent $event
   *   An exception event.
   */
  public function onException(HelsinkiProfiiliExceptionEvent $event): void {
    // phpcs:disable
    try {
      if ($this->auditLogService) {
        $exception = $event->getException();
        $message = [
          'operation' => 'EXCEPTION',
          'target' => [
            'message' => $exception->getMessage(),
            'type' => get_class($exception),
            'module' => 'helfi_helsinki_profiili',
          ],
        ];

        $this->auditLogService->dispatchEvent($message);
      }
    }
    catch (\Exception $e) {
    }
    // phpcs:enable
  }

}
