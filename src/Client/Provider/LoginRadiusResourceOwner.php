<?php
namespace Hola\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;

class LoginRadiusResourceOwner implements ResourceOwnerInterface
{
    use ArrayAccessorTrait;
    /**
     * Domain
     *
     * @var string
     */
    protected $domain;
    /**
     * Raw response
     *
     * @var array
     */
    protected $response;
    /**
     * Creates new resource owner.
     *
     * @param array  $response
     */
    public function __construct(array $response = array())
    {
        $this->response = $response;
    }
    /**
     * Get resource owner id
     *
     * @return string|null
     */
    public function getId()
    {

        return $this->getValueByKey($this->response, 'Uid');
    }
    /**
     * Get resource owner email
     *
     * @return string|null
     */
    public function getEmail()
    {
        $emailArray = $this->getValueByKey($this->response, 'Email');
        return current($emailArray)['Value'];
    }
    /**
     * Get resource owner name
     *
     * @return string|null
     */
    public function getFirstName()
    {
        return $this->getValueByKey($this->response, 'FirstName');
    }

    public function getLastName()
    {
        return $this->getValueByKey($this->response, 'LastName');
    }

    public function getFullName()
    {
        return $this->getValueByKey($this->response, 'FullName');
    }

    public function getGender()
    {
        return $this->getValueByKey($this->response, 'Gender');
    }


    /**
     * Set resource owner domain
     *
     * @param  string $domain
     *
     * @return ResourceOwner
     */
    public function setDomain($domain)
    {
        $this->domain = $domain;
        return $this;
    }
    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->response;
    }
}