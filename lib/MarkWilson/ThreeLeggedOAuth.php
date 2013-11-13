<?php

namespace MarkWilson;

use MarkWilson\TokenStorage\TokenStorageInterface;

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
     * Token storage interface
     *
     * @var TokenStorageInterface
     */
    private $tokenStorage;

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
     * @param string                   $baseUrl         OAuth base URL
     * @param string                   $consumerKey     Consumer key
     * @param string                   $consumerSecret  Consumer secret
     * @param TokenStorageInterface $persistentToken Session instance
     * @param string                   $requestBaseUrl  Base URL for subsequent requests
     */
    public function __construct($baseUrl, $consumerKey, $consumerSecret, TokenStorageInterface $persistentToken, $requestBaseUrl = null)
    {
        $this->baseUrl         = $baseUrl;
        $this->appUrl          = $_SERVER['PHP_SELF'];
        $this->tokenStorage = $persistentToken;
        $this->requestBaseUrl  = $requestBaseUrl;

        $this->oauth = new \OAuth($consumerKey, $consumerSecret, OAUTH_SIG_METHOD_HMACSHA1, OAUTH_AUTH_TYPE_URI);

        if ($this->tokenStorage->hasTokenData()) {
            $this->loadSessionToken();
        }

        $this->tokenStorage->initialise();
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
        return $this->tokenStorage->getStatus() === TokenStorageInterface::AUTHORISED;
    }

    /**
     * Check we've started authorising (i.e. request token has been issued)
     *
     * @return boolean
     */
    public function isPendingAuthorisation()
    {
        return $this->tokenStorage->getStatus() === TokenStorageInterface::PENDING_AUTHORISATION;
    }

    /**
     * Check if we've not started the oauth process
     *
     * @return boolean
     */
    public function isNotStarted()
    {
        return $this->tokenStorage->getStatus() === TokenStorageInterface::NOT_STARTED;
    }

    /**
     * Get the current oauth process status
     *
     * @return integer|null
     */
    public function getStatus()
    {
        return $this->tokenStorage->getStatus();
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

        $this->tokenStorage->setToken($token['oauth_token']);
        $this->tokenStorage->setSecret($token['oauth_token_secret']);

        $this->tokenStorage->setStatus(TokenStorageInterface::PENDING_AUTHORISATION);

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
        $token = $this->oauth->getAccessToken($this->buildUrl($this->accessTokenPath));

        $this->tokenStorage->setToken($token['oauth_token']);
        $this->tokenStorage->setSecret($token['oauth_token_secret']);

        $this->tokenStorage->setStatus(TokenStorageInterface::AUTHORISED);

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
     * @param string  $url          URL to access
     * @param array   $data         Post data
     * @param integer $formAuthType Change the form authentication type temporarily
     * @param boolean $debug        Debug the request
     *
     * @return string
     *
     * @throws \OAuthException If invalid request is made
     */
    public function post($url, array $data = array(), $formAuthType = OAUTH_AUTH_TYPE_AUTHORIZATION, $debug = false)
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
            $this->oauth->fetch($url, $data, OAUTH_HTTP_METHOD_POST);
        } catch (\OAuthException $e) {
            if ($debug) {
                var_dump($this->oauth->debugInfo);
            }

            throw $e;
        }

        // reset the auth type back to default
        $this->oauth->setAuthType(OAUTH_AUTH_TYPE_AUTHORIZATION);

        return $this->oauth->getLastResponse();
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
        $token  = $this->tokenStorage->getToken();
        $secret = $this->tokenStorage->getSecret();

        if ($token && $secret) {
            $this->oauth->setToken($token, $secret);
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
}
