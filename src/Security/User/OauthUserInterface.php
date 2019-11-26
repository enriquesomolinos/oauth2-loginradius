<?php

namespace Hola\OAuth2\Security\User;
/**
 * <strong>Name :  OauthUserInterface.php</strong><br>
 * <strong>Desc :  Put a description here</strong><br>
 *
 * PHP version 5.3
 *
 * @category  user_area
 * @package
 * @author    Development <desarrollo@hola-internet.com>
 * @copyright 2019 Hola.com
 * @license   Apache 2 License http://www.apache.org/licenses/LICENSE-2.0.html
 * @version   GIT: $Id$
 * @link      http://www.hola.com
 * @since     File available since Release 0.1.0
 */

interface OauthUserInterface{

    public function getAccessToken();

    public function setAccessToken($accessToken);

}