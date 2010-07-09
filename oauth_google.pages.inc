<?php
/**
 * @file
 * OAuth client library for Google Apps
 */

/**
 * Callback authorized token
 *
 * Warning: we just mark the token as authorized without further checking.
 *
 * @todo Check verification code
 */
function oauth_google_authorize_callback() {
  global $user;

  $req = DrupalOAuthRequest::from_request();

  $token_key = $req->get_parameter('oauth_token');
  
  if ($token = GoogleOAuthToken::load($token_key)) {
    $oauth_verifier = $req->get_parameter('oauth_verifier');
    $consumer = GoogleOAuthConsumer::load($token->consumer_key);
  }

  if ($token && $token->type == 'request' && $consumer) {
    $token->authorized = TRUE;
    $token->oauth_verifier = $oauth_verifier;
    $token->write(TRUE);
    // Get access token
    $client = new GoogleOAuthClient($consumer, $token);
    $client->setRequestToken($token);
    if ($access_token = $client->getAccessToken($oauth_verifier)) {
      $access_token->uid = $token->uid;
      $access_token->write();
      drupal_set_message(t('The application has been authorized and you have got an access token.'));
    }
    else {
      drupal_set_message(t('Error getting an access token.'));
    }
  }
  else {
    drupal_set_message(t('The authorization failed.'), 'error');
  }
  // Lacking a better idea, go back to user page
  return 'user/' . $user->uid;
}