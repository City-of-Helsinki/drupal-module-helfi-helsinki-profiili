<?php

namespace Drupal\helfi_helsinki_profiili\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Event submission create.
 */
class HelsinkiProfiiliExceptionEvent extends Event {

  const EVENT_ID = 'helfi_helfinki_profiili.exception';

  /**
   * Construct a new event.
   *
   * @param \Exception $exception
   *   The exception.
   */
  public function __construct(
    private \Exception $exception,
  ) {}

  /**
   * Get the exception.
   *
   * @return \Exception
   *   The exception.
   */
  public function getException() {
    return $this->exception;
  }

}
