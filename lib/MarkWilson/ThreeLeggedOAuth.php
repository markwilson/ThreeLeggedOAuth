<?php

namespace MarkWilson;

use Symfony\Component\HttpFoundation\Session\Session;

/**
 * OAuth wrapper class
 *
 * PECL OAuth library is required
 *
 * @author Mark Wilson <mark@89allport.co.uk>
 */
class ThreeLeggedOAuth
{
    /**
     * Authorisation status
     */
    const NOT_STARTED = 0;
    const PENDING_AUTHORISATION = 1;
    const AUTHORISED = 2;
    /**
     * @TODO: implement authorisation failed handler - should also allow user to initialise a restart of authorisation
     */
    const AUTHORISATION_FAILED = 3;

    /**
     * @TODO: implement session namespace
     */
    CONST SESSION_NAMESPACE = 'oauth';

    /**
     * Session instance
     *
     * @var Session
     */
    private $session;

    /**
     * OAuth instance
     *
     * @var \OAuth
     */
    private $oauth;

    /**
     * Base OAuth URL
     *
     * @var string
     */
    private $baseUrl = 'http://example.com/oauth/';

    /**
     * Request token path - appended to baseUrl
     *
     * @var string
     */
    private $requestTokenPath = 'request_token';

    /**
     * Authorise path - appended to baseUrl
     *
     * @var string
     */
    private $authorisePath = 'authorize';

    /**
     * Access token path - appended to baseUrl
     *
     * @var string
     */
    private $accessTokenPath = 'access_token';

    /**
     * App's own URL, used in final redirect from successful authorisation
     *
     * @var string
     */
    private $appUrl;

    /**
     * Base URL for subsequent requests
     *
     * @var string
     */
    private $requestBaseUrl;

    /**
     * Constructor.
     *
     * @param string  $baseUrl        OAuth base URL
     * @param string  $consumerKey    Consumer key
     * @param string  $consumerSecret Consumer secret
     * @param Session $session        Session instance
     * @param string  $requestBaseUrl Base URL for subsequent requests
     */
    public function __construct($baseUrl, $consumerKey, $consumerSecret, Session $session, $requestBaseUrl = null)
    {
        $this->baseUrl        = $baseUrl;
        $this->appUrl         = $_SERVER['PHP_SELF'];
        $this->session        = $session;
        $this->requestBaseUrl = $requestBaseUrl;

        $this->oauth = new \OAuth($consumerKey, $consumerSecret, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);
        $this->loadSessionToken();

        $this->initialiseSession();
    }

    /**
     * Set the app's own URL
     *
     * Defaults to PHP_SELF
     *
     * @param string $appUrl
     *
     * @return $this
     */
    public function setAppUrl($appUrl)
    {
        $this->appUrl = $appUrl;

        return $this;
    }

    /**
     * Set access token URL
     *
     * @param string $accessTokenUrl
     *
     * @return $this
     */
    public function setAccessTokenPath($accessTokenUrl)
    {
        $this->accessTokenPath = $accessTokenUrl;

        return $this;
    }

    /**
     * Set authorise URL
     *
     * @param string $authoriseUrl
     *
     * @return $this;
     */
    public function setAuthorisePath($authoriseUrl)
    {
        $this->authorisePath = $authoriseUrl;

        return $this;
    }

    /**
     * Set request token URL
     *
     * @param string $requestTokenUrl
     *
     * @return $this
     */
    public function setRequestTokenPath($requestTokenUrl)
    {
        $this->requestTokenPath = $requestTokenUrl;

        return $this;
    }

    /**
     * Check if the oauth has been fully authorised
     *
     * @return boolean
     */
    public function isAuthorised()
    {
        return $this->session->get('status') === self::AUTHORISED;
    }

    /**
     * Check we've started authorising (i.e. request token has been issued)
     *
     * @return boolean
     */
    public function isPendingAuthorisation()
    {
        return $this->session->get('status') === self::PENDING_AUTHORISATION;
    }

    /**
     * Check if we've not started the oauth process
     *
     * @return boolean
     */
    public function isNotStarted()
    {
        return $this->session->get('status') === self::NOT_STARTED;
    }

    /**
     * Get the current oauth process status
     *
     * @return integer|null
     */
    public function getStatus()
    {
        return $this->session->get('status');
    }

    /**
     * Request a token
     *
     * @param string $callbackUrl Callback URL
     *
     * @return void
     */
    public function requestToken($callbackUrl = null)
    {
        $token = $this->oauth->getRequestToken($this->buildUrl($this->requestTokenPath), $callbackUrl);

        $this->session->set('token', $token['oauth_token']);
        $this->session->set('secret', $token['oauth_token_secret']);

        $this->session->set('status', self::PENDING_AUTHORISATION);

        // @todo: allow user customisation of building redirect url
        $this->redirect($this->buildUrl($this->authorisePath) . '?oauth_token=' . $token['oauth_token']);
    }

    /**
     * Get a valid access token
     *
     * @return void
     */
    public function getAccessToken()
    {
        try {
            $token = $this->oauth->getAccessToken($this->buildUrl($this->accessTokenPath));
        } catch (\OAuthException $e) {
            $this->session->remove('token');
            $this->session->remove('secret');
            $this->session->set('status', self::NOT_STARTED);

            throw $e;
        }

        $this->setAccessToken($token['oauth_token'], $token['oauth_token_secret']);
    }

    /**
     * Set the access token
     *
     * @param string $token  Token string
     * @param string $secret Token secret string
     *
     * @return void
     */
    public function setAccessToken($token, $secret)
    {
        $this->session->set('token', $token);
        $this->session->set('secret', $secret);

        $this->session->set('status', self::AUTHORISED);

        $this->redirect($this->appUrl);
    }

    /**
     * Make a request to a URL
     *
     * @param string $url URL to access
     *
     * @return string
     */
    public function get($url)
    {
        if (is_string($this->requestBaseUrl)) {
            $url = $this->requestBaseUrl . $url;
        }

        $this->oauth->fetch($url);

        return $this->oauth->getLastResponse();
    }

    /**
     * Make a POST request to a URL
     *
     * @param string  $url               URL to access
     * @param array   $data              Post data
     * @param integer $formAuthType      Change the form authentication type temporarily
     * @param array   $additionalHeaders Additional headers to send
     * @param boolean $debug             Debug the request
     *
     * @return string
     *
     * @throws \OAuthException If invalid request is made
     */
    public function post($url, array $data = array(), $formAuthType = OAUTH_AUTH_TYPE_AUTHORIZATION, $additionalHeaders = array(), $debug = false)
    {
        if (is_string($this->requestBaseUrl)) {
            $url = $this->requestBaseUrl . $url;
        }

        if ($debug) {
            $this->oauth->enableDebug();
        }

        // change the auth type to use form data
        $this->oauth->setAuthType($formAuthType);

        try {
            $this->oauth->fetch($url, $data, OAUTH_HTTP_METHOD_POST, $additionalHeaders);
        } catch (\OAuthException $e) {
            if ($debug) {
                var_dump($this->oauth->debugInfo);
            }

            $this->session->set('last_exception', $e->getMessage());

            throw $e;
        }

        // reset the auth type back to default
        $this->oauth->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);

        return $this->oauth->getLastResponse();
    }

    /**
     * Make a PUT request to a URL
     *
     * @param string  $url          URL to access
     * @param array   $data         Put data
     * @param integer $formAuthType Change the form authentication type temporarily
     *
     * @return string
     *
     * @throws \OAuthException If invalid request is made
     */
    public function put($url, array $data = array(), $formAuthType = OAUTH_AUTH_TYPE_AUTHORIZATION)
    {
        if (is_string($this->requestBaseUrl)) {
            $url = $this->requestBaseUrl . $url;
        }

        // change the auth type to use form data
        $this->oauth->setAuthType($formAuthType);

        $this->oauth->fetch($url, $data, OAUTH_HTTP_METHOD_PUT);

        // reset the auth type back to default
        $this->oauth->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);

        return $this->oauth->getLastResponse();
    }

    /**
     * Make a request to a URL
     *
     * @param string $url URL to access
     *
     * @return string
     */
    public function delete($url)
    {
        if (is_string($this->requestBaseUrl)) {
            $url = $this->requestBaseUrl . $url;
        }

        $this->oauth->fetch($url, array(), OAUTH_HTTP_METHOD_DELETE);

        return $this->oauth->getLastResponse();
    }

    /**
     * Clear the current access token
     *
     * @return $this
     */
    public function logout()
    {
        $this->session->remove('token');
        $this->session->remove('secret');

        $this->session->set('status', self::NOT_STARTED);
    }

    /**
     * Has there been an exception raised?
     *
     * @return boolean
     */
    public function hasLastException()
    {
        return $this->session->has('last_exception');
    }

    /**
     * Get the last exception message
     *
     * @param boolean $clear Should it clear the message?
     *
     * @return string
     */
    public function getLastException($clear = true)
    {
        $message = $this->session->get('last_exception');

        if ($clear) {
            $this->session->remove('last_exception');
        }

        return $message;
    }

    /**
     * Get the access token in session
     *
     * @return array
     *
     * @throws \RuntimeException If no access token is available
     */
    public function getCurrentAccessToken()
    {
        if (!$this->isAuthorised()) {
            throw new \RuntimeException('No access token is available when not authorised');
        }

        return array(
            'token' => $this->session->get('token'),
            'secret' => $this->session->get('secret')
        );
    }

    /**
     * Set the current access token
     *
     * @param string       $token  Token key
     * @param string       $secret Token secret
     * @param integer|null $status New status to set
     *
     * @return $this
     *
     * @throws \InvalidArgumentException If the status is invalid
     */
    public function setCurrentAccessToken($token, $secret, $status = null)
    {
        $this->oauth->setToken($token, $secret);

        $this->session->set('token', $token);
        $this->session->set('secret', $secret);

        if ($status !== null) {
            if (!in_array($status, array(self::AUTHORISATION_FAILED, self::AUTHORISED, self::PENDING_AUTHORISATION, self::NOT_STARTED))) {
                throw new \InvalidArgumentException();
            }

            $this->session->set('status', $status);
        }

        return $this;
    }

    /**
     * Build the URL
     *
     * @param string $suffix Suffix for base URL
     *
     * @return string
     */
    private function buildUrl($suffix)
    {
        return $this->baseUrl . $suffix;
    }

    /**
     * Load in the token data from session
     *
     * @return void
     */
    private function loadSessionToken()
    {
        $token  = $this->session->get('token');
        $secret = $this->session->get('secret');

        if ($token && $secret) {
            $this->setCurrentAccessToken($token, $secret);
        }
    }

    /**
     * Redirect to a specified URL
     *
     * @param string $url Next URL
     */
    private function redirect($url)
    {
        header('Location: ' . $url);
        exit;
    }

    /**
     * Initialise the session, if required
     *
     * @return void
     */
    private function initialiseSession()
    {
        $session = $this->session;

        if (null === $session->get('status')) {
            $session->set('status', self::NOT_STARTED);
        }
    }
}
