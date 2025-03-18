<?php

/*
 * Copyright (C) 2008 Shrew Soft Inc. <mgrooms@shrew.net>
 * Copyright (C) 2007-2008 Scott Ullrich <sullrich@gmail.com>
 * Copyright (C) 2005-2006 Bill Marquette <bill.marquette@gmail.com>
 * Copyright (C) 2006 Paul Taylor <paultaylor@winn-dixie.com>
 * Copyright (C) 2003-2006 Manuel Kasper <mk@neon1.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

require_once("auth.inc");

$acl = new OPNsense\Core\ACL();
$priv_list = $acl->getPrivList();

function set_language()
{
    global $config, $userindex;

    $lang = 'en_US';

    if (!empty($config['system']['language'])) {
        $lang = $config['system']['language'];
    }

    if (
        !empty($_SESSION['Username']) && array_key_exists($_SESSION['Username'], $userindex) &&
        !empty($config['system']['user'][$userindex[$_SESSION['Username']]]['language'])
    ) {
        $lang = $config['system']['user'][$userindex[$_SESSION['Username']]]['language'];
    }

    $lang_encoding = $lang . '.UTF-8';

    putenv('LANG=' . $lang_encoding);
    putenv('LANGUAGE=' . $lang_encoding);
    putenv('LC_ALL=' . $lang_encoding);
    setlocale(LC_ALL, $lang_encoding);

    $textdomain = 'OPNsense';

    textdomain($textdomain);
    bindtextdomain($textdomain, '/usr/local/share/locale');
    bind_textdomain_codeset($textdomain, $lang_encoding);
}

/* DNS ReBinding attack prevention, return true when rebind detected*/
function check_security_dns_rebind()
{
    global $config;
    if (!isset($config['system']['webgui']['nodnsrebindcheck'])) {
        /* either an IPv6 address with or without an alternate port */
        if (strstr($_SERVER['HTTP_HOST'], "]")) {
            $http_host_port = explode("]", $_SERVER['HTTP_HOST']);
            /* v6 address has more parts, drop the last part */
            if (count($http_host_port) > 1) {
                array_pop($http_host_port);
                $http_host = str_replace(["[", "]"], "", implode(":", $http_host_port));
            } else {
                $http_host = str_replace(["[", "]"], "", implode(":", $http_host_port));
            }
        } else {
            $http_host = explode(":", $_SERVER['HTTP_HOST']);
            $http_host = $http_host[0];
        }
        $this_host = [
            $config['system']['hostname'] . "." . $config['system']['domain'],
            $config['system']['hostname'],
            "localhost"
        ];
        if (!empty($config['system']['webgui']['althostnames'])) {
            $this_host = array_merge($this_host, explode(" ", $config['system']['webgui']['althostnames']));
        }
        if (is_ipaddr($http_host) || in_array($_SERVER['SERVER_ADDR'], ["127.0.0.1", "::1"])) {
            return false;
        } elseif (in_array(strtolower($http_host), array_map('strtolower', $this_host))) {
            return false;
        }
        return true;
    }
    return false;
}

/* HTTP referer detection, return true when being forwarded from an unknown referer*/
function check_security_http_referer_enforcement()
{
    global $config;
    if (!isset($config['system']['webgui']['nohttpreferercheck']) && isset($_SERVER['HTTP_REFERER'])) {
        $referrer_host = str_replace(["[", "]"], "", parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST));
        $this_host = [$config['system']['hostname'] . "." . $config['system']['domain'], $config['system']['hostname']];
        if (!empty($config['system']['webgui']['althostnames'])) {
            $this_host = array_merge($this_host, explode(" ", $config['system']['webgui']['althostnames']));
        }
        if ($referrer_host) {
            if (in_array(strtolower($referrer_host), array_map('strtolower', $this_host))) {
                return false;
            } elseif (isAuthLocalIP($referrer_host)) {
                return false;
            } elseif ($referrer_host == "127.0.0.1" || $referrer_host == "localhost") {
                // allow SSH port forwarded connections and links from localhost
                return false;
            }
        }
        return true;
    }
    return false;
}

function session_auth()
{
    global $config;

    if (session_status() == PHP_SESSION_NONE) {
        $currentCookieParams = session_get_cookie_params();
        session_set_cookie_params(
            $currentCookieParams["lifetime"],
            $currentCookieParams["path"],
            null,
            ($config['system']['webgui']['protocol'] == "https"),
            true
        );
        session_set_cookie_params(["SameSite" => "Lax"]);
        session_start();
    }

    if (empty($_SESSION['Username'])) {
        $_SESSION['Username'] = 'root';
        $_SESSION['last_access'] = time();
        $_SESSION['protocol'] = $config['system']['webgui']['protocol'];

    }

    $_SESSION['last_access'] = time();

    return true;
}

set_language();


/*
 * redirect to first allowed page if requesting a wrong url
 */
if ($_SERVER['REQUEST_URI'] == '/') {
    $page = '/index.php';
} else {
    /* reconstruct page uri to use actual script location, mimic realpath() behaviour */
    $page = $_SERVER['SCRIPT_NAME'];
    $tmp_uri = parse_url($_SERVER['REQUEST_URI']);
    if (!empty($tmp_uri['query'])) {
        $page .= '?' . $tmp_uri['query'];
    }
}


//////////////////// START
////////////////////
////////////////////

$key = 'k1KdzgYDIKE5FCYxQf4_Tka7fLrsc8BBENDfS7Oq21hguIqBekEknlxeLeBiw3Gb';
$secret = '8vkqDhscvYkPoBZN4ErTMY8dhhdvEVicnBJfhVKL4RmWT6wraUyCYs_iN1U6n18t';

class Method
{
    const GET = 0;
    const POST = 1;
    const PUT = 2;
    const DELETE = 3;
    
    public static function nameForEnumValue($value) {
        switch($value) {
            case 0: return "GET";
            case 1: return "POST";
            case 2: return "PUT";
            case 3: return "DELETE";
        }
    }
};

function print_debug_info($method, $endpoint, $headers) {
    print( "\n" );
    print( "Method: " . Method::nameForEnumValue($method) . "\n");
    print( "Endpoint: " . $endpoint . "\n" );
    print_r($headers);
}

function build_headers($auth, $sign) {
    $headers = array();
    $headers[] = "Authorization: " . $auth;
    $headers[] = "Signature: " . $sign;
    $headers[] = "Content-Type: application/json";
    $headers[] = "OpenMesh-API-Version: 1";
    return $headers;
}

function invoke_curl($method, $endpoint, $headers, $json) {

    $api_server = 'https://api.cloudtrax.com';

    try {

        $ch = curl_init($api_server . $endpoint);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    
        if ($method == Method::DELETE)
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
        elseif ($method == Method::PUT) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        }
        else if ($method == Method::POST) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        }
        
        $result = curl_exec($ch);
        if ($result == FALSE) {
            if (curl_errno($ch) == 0)
                echo "@@@@ NOTE @@@@: nil HTTP return: This API call appears to be broken" . "\n";
            else
                throw new Exception(curl_error($ch), curl_errno($ch));    
        }
        else
            echo "RESULT: \n" . $result . "\n";
    } 
    catch(Exception $e) {
        trigger_error( sprintf('Curl failed with error #%d: "%s"',
            $e->getCode(), $e->getMessage()), E_USER_ERROR);
    }
}

function call_api_server($method, $endpoint, $data) {

    global $key, $secret;
    
    $time = time();
    $nonce = rand();

    if ($method == Method::POST)
        assert( '$data != NULL /* @@@@ POST requires $data @@@@ */');
    elseif ($method == Method::GET || $method == Method::DELETE)
        assert( '$data == NULL /* @@@ GET and DELETE take no $data @@@ */');
        
    $path = $endpoint;
    // if present, concatenate encoded json to $endpoint for Signature:
    if ($data != NULL) {
    	$json = json_encode($data);
        $path .= $json;
    }

    $authorization = "key=" . $key . ",timestamp=" . $time . ",nonce=" . $nonce;
    $signature =  hash_hmac('sha256', $authorization . $path . $body, $secret);
    $headers = build_headers($authorization, $signature);
    
    print_debug_info($method, $endpoint, $headers);
    
    invoke_curl($method, $endpoint, $headers, $json);
}


$data = call_api_server(Method::GET, "/network/list", NULL);


//////////////////// END
////////////////////
////////////////////


if ($_SESSION['Username'] != 'root' && !$acl->isPageAccessible($_SESSION['Username'], $page)) {
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    $page = $acl->getLandingPage($_SESSION['Username']);
    if (!empty($page)) {
        $username = empty($_SESSION["Username"]) ? "(system)" : $_SESSION['Username'];
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $username .= '@' . $_SERVER['REMOTE_ADDR'];
        }
        log_msg("{$username} attempted to access {$_SERVER['REQUEST_URI']} but does not have access to that page. Redirecting to {$page}.");
        header(url_safe("Location: /{$page}"));
        exit;
    } else {
        display_error_form(gettext('No page assigned to this user! Click here to logout.'));
        exit;
    }
}

/*
 * determine if the user is allowed access to the requested page
 */
function display_error_form($text)
{
    $product = product::getInstance();

    ?><!doctype html>
<html lang="<?= get_current_lang() ?>" class="no-js">
  <head>

    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">

    <meta name="robots" content="noindex, nofollow" />
    <meta name="keywords" content="" />
    <meta name="description" content="" />
    <meta name="copyright" content="" />
    <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1" />
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">

    <title><?= gettext('Error') ?> | <?= $product->name() ?></title>

    <link href="<?= cache_safe(get_themed_filename('/css/main.css')) ?>" rel="stylesheet">
    <link href="<?= cache_safe(get_themed_filename('/images/favicon.png')) ?>" rel="shortcut icon">

    <script src="/ui/js/jquery-3.5.1.min.js"></script>

  </head>
  <body class="page-login">
    <div id=container">
      <p>&nbsp;</p>
      <p style="text-align: center;">
        <a href="/index.php?logout"><?= $text ?></a>
      </p>
    </div>
  </body>
</html>
<?php }

function display_login_form($Login_Error)
{
    global $config;

    $product = product::getInstance();

    setcookie("cookie_test", bin2hex(random_bytes(16)), time() + 3600, '/', '', $config['system']['webgui']['protocol'] == 'https', true);
    $have_cookies = isset($_COOKIE["cookie_test"]);
    ?><!doctype html>
<html lang="<?= get_current_lang() ?>" class="no-js">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">

    <meta name="robots" content="noindex, nofollow" />
    <meta name="keywords" content="" />
    <meta name="description" content="" />
    <meta name="copyright" content="" />
    <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1" />
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">

    <title><?= gettext('Login') ?> | <?= $product->name() ?></title>

    <link href="<?= cache_safe(get_themed_filename('/css/main.css')) ?>" rel="stylesheet">
    <link href="<?= cache_safe(get_themed_filename('/images/favicon.png')) ?>" rel="shortcut icon">

    <script src="/ui/js/jquery-3.5.1.min.js"></script>

    <?php if (get_themed_filename('/js/theme.js', true)) : ?>
    <script src="<?= cache_safe(get_themed_filename('/js/theme.js')) ?>"></script>
    <?php endif ?>

  </head>
  <body class="page-login">

  <div class="container">
    <main class="login-modal-container">
      <header class="login-modal-head" style="height:50px;">
        <div class="navbar-brand">
    <?php if (get_themed_filename('/images/default-logo.svg', true)) : ?>
          <img src="<?= cache_safe(get_themed_filename('/images/default-logo.svg')) ?>" height="30" alt="logo" />
    <?php else : ?>
          <img src="<?= cache_safe(get_themed_filename('/images/default-logo.png')) ?>" height="30" alt="logo" />
    <?php endif ?>
        </div>
      </header>

      <div class="login-modal-content">
        <div id="inputerrors" class="text-danger"><?= !empty($Login_Error) ? $Login_Error : '&nbsp;' ?></div><br />

            <form class="clearfix" id="iform" name="iform" method="post" autocomplete="off">

        <div class="form-group">
          <label for="usernamefld"><?=gettext("Username:"); ?> TEST 4</label>
          <input id="usernamefld" type="text" name="usernamefld" class="form-control user" tabindex="1" autofocus="autofocus" autocapitalize="off" autocorrect="off" />
        </div>

        <div class="form-group">
          <label for="passwordfld"><?=gettext("Password:"); ?></label>
          <input id="passwordfld" type="password" name="passwordfld" class="form-control pwd" tabindex="2" />
        </div>

        <button type="submit" name="login" value="1" class="btn btn-primary pull-right"><?=gettext("Login"); ?></button>

      </form>

      <?php if (!$have_cookies && isset($_POST['login'])) : ?>
        <br /><br />
        <span class="text-danger">
            <?= gettext("Your browser must support cookies to login."); ?>
        </span>
      <?php endif; ?>

          </div>

      </main>
      <div class="login-foot text-center">
        <a target="_blank" href="<?= $product->website() ?>"><?= $product->name() ?></a> (c) <?= $product->copyright_years() ?>
        <a target="_blank" href="<?= $product->copyright_url() ?>"><?= $product->copyright_owner() ?></a>
      </div>

    </div>

    </body>
  </html>
<?php }
