<?php

namespace Hola\OAuth2\Security\Authorization\Voter;

use Hola\OAuth2\Client\Provider\Exception\LoginRadiusProviderException;
use Hola\OAuth2\Security\User\OauthUserInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;

class OAuthLoginRadiusAuthenticatedVoter extends AuthenticatedVoter
{
    private $authenticationTrustResolver;
    private $userProvider;

    public function __construct(AuthenticationTrustResolverInterface $authenticationTrustResolver, ClientRegistry $clientRegistry)
    {
        $this->authenticationTrustResolver = $authenticationTrustResolver;
        $this->userProvider =$clientRegistry->getClient('loginradius_oauth')->getOAuth2Provider();
    }
    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        $result = VoterInterface::ACCESS_ABSTAIN;
        if(isset($subject) && $this->supports($subject) && $token && $token->getUser()){
            if($token->getUser() instanceof OauthUserInterface){
                $user = $token->getUser();
                try{
                    $this->userProvider->validateAccessToken($user->getAccessToken());
                }catch( LoginRadiusProviderException $e){
                    $result = VoterInterface::ACCESS_DENIED;
                }
            }
        }
        return $result;
    }

    public function supports(Request $request)
    {
        return $request->attributes->get('_route')!== 'connect_loginradius_check';
    }
}
