<?php

namespace MarkWilson\TokenStorage;

use Symfony\Component\HttpFoundation\Session\Session;

/**
 * Session token storage
 *
 * @package MarkWilson\TokenStorage
 * @author  Mark Wilson <mark@89allport.co.uk>
 */
class SessionPersistentToken implements TokenStorageInterface
{
    /**
     * @TODO: implement session namespace
     */
    const SESSION_NAMESPACE = 'oauth';

    /**
     * Session
     *
     * @var Session
     */
    private $session;

    /**
     * Constructor.
     *
     * @param Session $session
     */
    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    /**
     * Initialise the token storage
     *
     * @return $this
     */
    public function initialise()
    {
        $session = $this->session;

        if (!$session->get('status')) {
            $session->set('status', TokenStorageInterface::NOT_STARTED);
        }

        return $this;
    }

    /**
     * Token exists in storage
     *
     * @return boolean
     */
    public function hasTokenData()
    {
        return $this->getToken() && $this->getSecret();
    }

    /**
     * Set the token
     *
     * @param string $token New token
     *
     * @return $this
     */
    public function setToken($token)
    {
        $this->session->set('token', $token);

        return $this;
    }

    /**
     * Get the token
     *
     * @return string
     */
    public function getToken()
    {
        $this->session->get('token');
    }

    /**
     * Set the secret
     *
     * @param string $secret New secret
     *
     * @return $this
     */
    public function setSecret($secret)
    {
        $this->session->set('secret', $secret);

        return $this;
    }

    /**
     * Get the secret
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->session->get('secret');
    }

    /**
     * Set the current status
     *
     * @param string $status New status
     *
     * @return $this
     */
    public function setStatus($status)
    {
        $this->session->set('status', $status);

        return $this;
    }

    /**
     * Get the current status
     *
     * @return string
     */
    public function getStatus()
    {
        return $this->session->get('status');
    }
}
