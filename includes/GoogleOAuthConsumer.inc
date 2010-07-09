<?php
// $Id$

/**
 * OAuth consumer for Google API
 * 
 * We need a wrapper class to get always a client consumer instead of a provider consumer
 * 
 * @author Jose A. Reyero, http://www.developmentseed.org
 */
class GoogleOAuthConsumer extends DrupalOAuthConsumer {
  public $provider_consumer = FALSE;
  public $name = 'Google OAuth';

  function __construct($key, $secret, $callback_url = NULL, $params=array()) {
    // Unlike for Drupal consumer, we have a url by default
    $callback_url = $callback_url ? $callback_url : oauth_google_authorize_url();
    parent::__construct($key, $secret, $callback_url, FALSE, $params);
  }

  /**
   * Deletes the consumer with the key from the database.
   *
   * @param string $key
   *  The consumer key.
   * @param bool $provider_consumer
   *  Optional. Whether the consumer we're about to delete is a provider or
   *  consumer consumer. Defaults to TRUE.
   * @return void
   */
  public static function deleteConsumer($key) {
    parent::deleteConsumer($key, FALSE);
  }

  /**
   * Gets the consumer with the specified key
   *
   * @param string $key
   *  The key of the consumer to get
   * @param bool $provider_consumer
   *  Optional. Whether the consumer we're about to load is a provider or
   *  consumer consumer. Defaults to TRUE.
   * @return DrupalOAuthConsumer
   *  The loaded consumer object or FALSE if load failed
   */
  public static function load($key) {
    return parent::load($key, FALSE);
  }

  /**
   * Constructs a consumer from a db-result resource
   *
   * @param resource $res
   *  A database result resource
   * @return DrupalOAuthConsumer
   *  The constructed consumer object or NULL if no rows could be read or construction failed
   */
  public static function fromResult($res) {
    if ($data = db_fetch_array($res)) {
      if (!empty($data['configuration'])) {
        $data['configuration'] = unserialize($data['configuration']);
      }
      $data['in_database'] = TRUE;
      return new GoogleOAuthConsumer($data['consumer_key'], $data['secret'], $data['callback_url'], $data);
    }
    return NULL;
  }
}