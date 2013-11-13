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
    // optionally pass through the callback url here
    $oauth->requestToken('http://...');
}
````

### Twitter home timeline (very) basic example

```` php
<?php

require_once 'vendor/autoload.php';

$session = new Symfony\Component\HttpFoundation\Session\Session();

$oauth = new MarkWilson\ThreeLeggedOAuth(
    'https://api.twitter.com/oauth/',
    '<consumer key>',
    '<consumer secret>',
    $session,
    'https://api.twitter.com/1.1'
);

if ($oauth->isAuthorised()) {
    $response = $oauth->get('/statuses/home_timeline.json');

    $jsonDecoded = json_decode($response);

    if ($jsonDecoded) {
        foreach ($jsonDecoded as $tweet) {
            echo $tweet->user->name . ': ' . $tweet->text . '<br />';
        }
    } else {
        echo $response;
    }
} elseif ($oauth->isPendingAuthorisation()) {
    $oauth->getAccessToken();
} else {
    $oauth->requestToken('http://' . $_SERVER['HTTP_HOST'] . '/');
}
````
