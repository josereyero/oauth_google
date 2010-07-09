<?php
// $Id: DrupalOAuthClient.inc,v 1.1 2009/06/23 06:55:59 jreyero Exp $

/**
 * OAuth client for Google Data API
 */
class GoogleOAuthClient extends DrupalOAuthClient {
  const SERVER = 'https://www.google.com/accounts';
  const USER_AUTHORIZATION_PATH = '/OAuthAuthorizeToken';
  const REQUEST_TOKEN_PATH = '/OAuthGetRequestToken';
  const ACCESS_TOKEN_PATH = '/OAuthGetAccessToken';

  protected $requestTokenUrl = 'https://www.google.com/accounts/OAuthGetRequestToken';
  protected $userAuthorizationUrl = 'https://www.google.com/accounts/OAuthAuthorizeToken';
  protected $accessTokenUrl = 'https://www.google.com/accounts/OAuthGetAccessToken';

  public $scope;
  public $oauth_callback;

    /**
   * Creates an instance of the DrupalOAuthClient.
   *
   * @param DrupalOAuthConsumer $consumer
   *  The consumer.
   * @param OAuthToken $request_token
   *  Optional. A request token to use.
   * @param OAuthSignatureMethod $signature_method
   *  Optional. The signature method to use.
   */
  public function __construct($consumer, $request_token = NULL, $signature_method = NULL) {
    // We just override the constructor to pass on the right signature_method.
    // As it is a static function, calling the parent's constructor will use parent's method
    $signature_method = $signature_method ? $signature_method : self::signatureMethod();
    parent::__construct($consumer, $request_token, $signature_method);
  }

  public static function signatureMethod() {
    static $sign;
    if(!$sign) {
      $sign = new OAuthSignatureMethod_HMAC_SHA1();
    }
    return $sign;
  }

  public function setRequestToken($token) {
    $this->requestToken = $token;
  }
  
  public function getRequestToken($scope = NULL, $callback_url = NULL) {
    if (!$this->requestToken) {
      $query = array(
        'scope' => $scope ? $scope : $this->scope,
        'oauth_callback' => $callback_url ? $callback_url : $this->consumer->callback_url,     
      );

      $response = $this->get(self::REQUEST_TOKEN_PATH, TRUE, $query);

      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid request token was returned');
      }
      
      $props = array(
        'type' => 'request',
        'consumer_key' => $this->consumer->key,
        'provider_token' => FALSE,
      );

      $this->requestToken = new GoogleOAuthToken($params['oauth_token'], $params['oauth_token_secret'], $props);
    }

    return $this->requestToken;
  }

  /**
   * @param $domain
   *   Optional Google Apps domain
   */
  public function getAuthorizationUrl($domain = NULL) {
    $params = array(
      'oauth_token' => $this->requestToken->key,
    );
    if ($domain) {
      $params['hd'] = $domain;
    }
    return self::SERVER . self::USER_AUTHORIZATION_PATH . '?' . http_build_query($params, NULL, '&');
  }

  public function getAccessToken($oauth_verifier = NULL) {
    if (!$this->accessToken) {
      $query = array('oauth_verifier' => $oauth_verifier);

      $response = $this->get(self::ACCESS_TOKEN_PATH, TRUE, $query);
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid access token was returned');
      }
      $props = array(    
        'type' => 'access',
        'consumer_key' => $this->consumer->key,
        'provider_token' => FALSE,        
      );

      $this->accessToken = new GoogleOAuthToken($params['oauth_token'], $params['oauth_token_secret'], $props);
    }

    return $this->accessToken;
  }

  /**
   * HTTP GET Request for token management. 
   * 
   * This will add authorization parameters into the get request
   * 
   * @param $token
   *   Optional token to use instead of Access Token
   */
  protected function get_token($url, $params = array(), $token = NULL) {
    $token = $token ? $token : $this->accessToken;
    $req = OAuthRequest::from_consumer_and_token($this->consumer, $token,
      "GET", $url, $params);
    $req->sign_request(self::signatureMethod(), $this->consumer, $token);


    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, $req->to_url());
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
      throw new Exception($error);
    }

    $result = $this->interpretResponse($response);
    if ($result->responseCode != 200) {
      throw new Exception('Failed to fetch data from url (HTTP response code ' . $result->responseCode . '): ' . $result->responseMessage, $result->responseCode);
    }

    return $result->body;
  }

}

