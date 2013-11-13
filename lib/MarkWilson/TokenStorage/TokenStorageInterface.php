<?php

namespace MarkWilson\TokenStorage;

/**
 * Interface for token persistence between OAuth stages
 *
 * @author Mark Wilson <mark@89allport.co.uk>
 */
interface TokenStorageInterface
{
    /**
     * Authorisation status
     */
    const NOT_STARTED = 0;
    const PENDING_AUTHORISATION = 1;
    const AUTHORISED = 2;
    const AUTHORISATION_FAILED = 3;

    /**
     * Initialise the token storage
     *
     * @return $this
     */
    public function initialise();

    /**
     * Token exists in storage
     *
     * @return boolean
     */
    public function hasTokenData();

    /**
     * Set the token
     *
     * @param string $token New token
     *
     * @return $this
     */
    public function setToken($token);

    /**
     * Get the token
     *
     * @return string|null
     */
    public function getToken();

    /**
     * Set the secret
     *
     * @param string $secret New secret
     *
     * @return $this
     */
    public function setSecret($secret);

    /**
     * Get the secret
     *
     * @return string|null
     */
    public function getSecret();

    /**
     * Set the current status
     *
     * @param string $status New status
     *
     * @return $this
     */
    public function setStatus($status);

    /**
     * Get the current status
     *
     * @return string|null
     */
    public function getStatus();
}
