<?php
/**
 * Google Apps site wide settings
 */
function oauth_google_admin_settings_form() {
  $form['oauth_google_consumer_key'] = array(
    '#type' => 'textfield',
    '#maxlength' => 32,
    '#title' => t('Key'),
    '#default_value' => variable_get('oauth_google_consumer_key', ''),
    '#required' => TRUE,
  );
  $form['oauth_google_consumer_secret'] = array(
    '#type' => 'textfield',
    '#maxlength' => 32,
    '#title' => t('Secret'),
    '#default_value' => variable_get('oauth_google_consumer_secret', ''),
    '#required' => TRUE,
  );
  $form['oauth_google_default_scope'] = array(
    '#type' => 'textarea',
    '#title' => t('Scope'),
    '#default_value' => variable_get('oauth_google_default_scope', OAUTH_GOOGLE_DEFAULT_SCOPE),
    '#required' => TRUE,
  );
  $form['oauth_google_default_domain'] = array(
    '#type' => 'textfield',
    '#title' => t('Domain'),
    '#default_value' => variable_get('oauth_google_default_domain', 'default'),
    '#description' => t('Google Apps domain. Let default value to use regular Google accounts.'),
  );
  return system_settings_form($form);
}

