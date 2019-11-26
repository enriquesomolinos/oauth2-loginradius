<?php

namespace Hola\OAuth2\Security\User;

use KnpU\OAuth2ClientBundle\Security\User\OAuthUser;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;

class OAuthLoginRadiusUserProvider implements UserProviderInterface
{
    private $roles;
    protected $tokenStorage;
    protected $clientRegistry;

    public function __construct(ClientRegistry $clientRegistry, TokenStorageInterface $tokenStorage, array $roles = ['ROLE_USER', 'ROLE_OAUTH_USER'])
    {
        $this->roles = $roles;
        $this->tokenStorage = $tokenStorage;
        $this->clientRegistry = $clientRegistry;
    }

    public function loadUserByUsername($username): UserInterface
    {
        return new OAuthUser($username, $this->roles);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
       // if ($user instanceof OauthUserInterface) {

        $registry = $this->clientRegistry
            ->getClient('loginradius_oauth');
       // var_dump($registry->getAccessToken());die;
       // throw new \Exception();
       // var_dump($user);die;
        //var_dump( $this->tokenStorage);die;
          //  throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        //}
        if (!$user instanceof OAuthUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class): bool
    {
        return true;
    }
}
