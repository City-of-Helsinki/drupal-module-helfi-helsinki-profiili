<?php

namespace Drupal\helfi_helsinki_profiili\EventSubscriber;

use Drupal\helfi_helsinki_profiili\Event\HelsinkiProfiiliExceptionEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Monitors submission view events and logs them to audit log.
 */
class HelsinkiProfiiliExceptionEventSubscriber implements EventSubscriberInterface {

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
    // phpcs:disable
    try {
      // Try to get service, this will throw exception if not found.
      $auditlogService = \Drupal::service('helfi_audit_log.audit_log');
      if ($auditlogService) {
        $exception = $event->getException();
        $message = [
          'operation' => 'EXCEPTION',
          'target' => [
            'message' => $exception->getMessage(),
            'type' => get_class($exception),
            'module' => 'helfi_helsinki_profiili',
          ],
        ];

        $auditlogService->dispatchEvent($message);
      }
    }
    catch (\Exception $e) {
    }
    // phpcs:enable
  }

}
