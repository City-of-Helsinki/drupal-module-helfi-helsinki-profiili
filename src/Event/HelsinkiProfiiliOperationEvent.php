<?php

namespace Drupal\helfi_helsinki_profiili\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Event submission create.
 */
class HelsinkiProfiiliOperationEvent extends Event {

  const EVENT_ID = 'helfi_helfinki_profiili.operation';

  /**
   * Construct a new event.
   *
   * @param string $name
   *   Name of operation.
   */
  public function __construct(
    private string $name,
  ) {}

  /**
   * Get the name.
   *
   * @return string
   *   Name of the operation.
   */
  public function getName() {
    return $this->name;
  }

}
