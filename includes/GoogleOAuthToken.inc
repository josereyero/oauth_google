<?php
// $Id: DrupalOAuthToken.inc,v 1.3 2009/07/24 14:14:01 hugowetterberg Exp $

class GoogleOAuthToken extends DrupalOAuthToken {
  // Special token types for not mixing them with regular oauth tokens
  const GDATA_REQUEST_TOKEN = 'request';
  const GDATA_ACCESS_TOKEN = 'access';
  
  public $oauth_verifier = '';
  public $provider_token = FALSE;
  /**
   * Constructs a token from a db-result resource
   *
   * @param resource $res
   *  A database result resource
   * @return DrupalOAuthToken
   *  The constructed token object or NULL if no rows could be read or construction failed
   */
  public static function fromResult($res) {
    if ($data = db_fetch_array($res)) {
      $data['services'] = json_decode($data['services']);
      $data['in_database'] = TRUE;
      return new GoogleOAuthToken($data['token_key'], $data['secret'], $data);
    }
    return NULL;
  }
  
  /**
   * Gets the token with the specified key. This is always a consumer token.
   *
   * @param string $key
   *  The key of the token to get
   */
  public static function load($key) {
    return parent::load($key, FALSE);
  }
}