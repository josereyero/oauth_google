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
  
  if ($token = DrupalOAuthToken::load($token_key, FALSE)) {
    $oauth_verifier = $req->get_parameter('oauth_verifier');
    $consumer = DrupalOAuthConsumer::load($token->consumer_key, FALSE);
  }

  if ($token && $token->type == 'request' && $consumer) {
    $token->authorized = TRUE;
    $token->oauth_verifier = $oauth_verifier;
    $token->write(TRUE);
    // Get access token
    $client = new DrupalOAuthClient($consumer, $token);
    $options = array('verifier' => $oauth_verifier);
    if ($access_token = $client->getAccessToken(NULL, $options)) {
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
  drupal_goto('user/' . $user->uid);
}

/**
 * User authentication
 */
function oauth_google_user_account_form($form_state, $account, $consumer = NULL) {
  $consumer = $consumer ? $consumer : oauth_google_get_consumer();
  $form['account'] = array('#type' => 'value', '#value' => $account);
  $form['consumer'] = array('#type' => 'value', '#value' => $consumer);
  // These are GoogleOauthToken objects
  $request_token = oauth_google_get_user_token($account, $consumer, 'request');
  $access_token = oauth_google_get_user_token($account, $consumer, 'access');
  $form['request_token'] = array('#type' => 'value', '#value' => $request_token);
  $form['access_token'] = array('#type' => 'value', '#value' => $access_token);

  $form['status'] = array(
    '#type' => 'item',
    '#title' => t('Status'),
  );
  $form['options'] = array('#type' => 'fieldset');
  if (!$access_token && !$request_token) {
    $form['options']['request'] = array('#type' => 'submit', '#value' => t('Request token'));
  }
  else {
    $tokens = array();
    if ($request_token) {
      $tokens[] = array(t('Request token'), $request_token->authorized ? t('Authorized') : t('Needs authorization'), $request_token->key, format_date($request_token->created));
    }
    if ($access_token) {
      $tokens[] = array(t('Access token'), t('OK'), $access_token->key, format_date($access_token->created));
      $status = t('You already have an access token.');
    }
    else {
      if ($request_token->authorized) {
        $status = t('You have an already authorized token.');
      }
      else {
        $status = t('You have a request token not authorized yet.');
        $form['options']['authorize'] = array('#type' => 'submit', '#value' => t('Authorize token'));
      }
    }
    $form['options']['reset'] = array('#type' => 'submit', '#value' => t('Reset'));
    $header = array(t('Type'), t('Status'), t('Token'), t('Date'));
    $form['tokens'] = array(
      '#type' => 'item',
      '#value' => theme('table', $header, $tokens),
    );
  }
  $form['status']['#value'] = isset($status) ? $status : '';
  return $form;
}

/**
 * User authentication, form submission
 */
function oauth_google_user_account_form_submit($form, $form_state) {
  $op = !empty($form_state['values']['op']) ? $form_state['values']['op'] : '';
  $account = $form_state['values']['account'];
  $consumer = $form_state['values']['consumer'];
  $access_token = $form_state['values']['access_token'];
  $request_token = $form_state['values']['request_token'];

  switch ($op) {
    case t('Reset'):
      if ($access_token) {
        DrupalOauthToken::deleteToken($access_token->key, FALSE);
      }
      if ($request_token) {
        DrupalOauthToken::deleteToken($request_token->key, FALSE);
      }
      break;
    case t('Request token');
      if ($token = oauth_google_create_request_token($consumer, $account)) {
        drupal_set_message(t('You got a new request token'));
      }
      else {
        drupal_set_message(t('Your token request failed'), 'error');
      }
      break;
    case t('Authorize token');
      $url = oauth_google_authorize_url($consumer, $request_token);
      drupal_goto($url);
      break;
  }
}
