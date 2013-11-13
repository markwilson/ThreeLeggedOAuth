# 3-legged OAuth

## Installation

### Via composer

Add `markwilson/three-legged-oauth` to your composer.json requirements.

```` sh
php composer.phar install
````

## Usage

```` php
<?php

require_once 'vendor/autoload.php';

$session = new Symfony\Component\HttpFoundation\Session\Session();

$oAuth = new MarkWilson\ThreeLeggedOAuth(
    '<base oauth url>',
    '<consumer key>',
    '<consumer secret>',
    $session,
    '<base app url>'
);

if ($oauth->isAuthorised()) {
    // already authorised, let's connect to the app
    $response = $oauth->get('<app endpoint>');

    echo $response;
} elseif ($oauth->isPendingAuthorisation()) {
    // waiting for authorisation, request access
    $oauth->getAccessToken();
} else {
    // no authorisation yet, start request
    $oauth->requestToken();
}
````
