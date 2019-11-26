<?php
namespace Hola\OAuth2\Security\Handler;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;

class OAuthLoginRadiusLogoutHandler implements LogoutHandlerInterface
{
    private $userProvider;

    public function __construct(ClientRegistry $clientRegistry)
    {

        $this->userProvider =$clientRegistry->getClient('loginradius_oauth')->getOAuth2Provider();
    }

    public function logout(
        Request $request, Response $response, TokenInterface $token
    )
    {
            return $this->userProvider->logout($token->getUser()->getAccessToken());
    }

}