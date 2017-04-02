<?php

namespace Kayue\WordpressBundle\Tests\Security\Http;

use Kayue\WordpressBundle\Security\Authentication\Token\WordpressToken;
use Kayue\WordpressBundle\Security\Http\WordpressCookieService;
use Kayue\WordpressBundle\Wordpress\AuthenticationCookieManager;
use Kayue\WordpressBundle\Wordpress\ConfigurationManager;
use Symfony\Component\HttpFoundation\Request;

class WordpressCookieServiceTest extends \PHPUnit_Framework_TestCase
{
    public function testAutoLoginCookie()
    {
        $service = $this->getService();
        $request = new Request();
        $request->cookies->set($this->getAuthenticationCookieManagerMock()->getLoggedInCookieName(), 'admin|9999999999999|hmac');

        /** @var $token WordpressToken */
        $token = $service->autoLogin($request);

        $this->assertTrue($token instanceof WordpressToken);
        $this->assertFalse($token->isAuthenticated());
    }

    public function testAutoLoginCookieWithEmptyRequest()
    {
        $service = $this->getService();
        $request = new Request();

        $this->assertNull($service->autoLogin($request));
    }

    public function testAutoLoginCookieWithInvalidCookie()
    {
        $service = $this->getService();
        $request = new Request();
        $request->cookies->set($this->getAuthenticationCookieManagerMock()->getLoggedInCookieName(), 'something');

        $this->assertNull($service->autoLogin($request));
    }

    public function testAutoLoginCookieWithUserNotFound()
    {
        $service = $this->getService();
        $request = new Request();
        $request->cookies->set($this->getAuthenticationCookieManagerMock()->getLoggedInCookieName(), 'nobody|9999999999999|hmac');

        $this->assertNull($service->autoLogin($request));
    }

    public function testAutoLoginCookieWithInvalidHmac()
    {
        $service = $this->getService();
        $request = new Request();
        $request->cookies->set($this->getAuthenticationCookieManagerMock()->getLoggedInCookieName(), 'admin|9999999999999|invalid');

        $this->assertNull($service->autoLogin($request));
    }

    public function testAutoLoginCookieWithExpiredCookie()
    {
        $service = $this->getService();
        $request = new Request();
        $request->cookies->set($this->getAuthenticationCookieManagerMock()->getLoggedInCookieName(), 'admin|1|hmac');

        $this->assertNull($service->autoLogin($request));
    }

    private function getService()
    {
        $wordpressCookieService = new WordpressCookieService(
            $this->getAuthenticationCookieManagerMock(),
            $this->getUserProviderMock()
        );

        return $wordpressCookieService;
    }

    private function getAuthenticationCookieManagerMock()
    {
        $mock = $this->getMock(AuthenticationCookieManager::class,
            array('generateHmac'),
            array($this->getConfigurationManager())
            );

        $mock->expects($this->any())
            ->method('generateHmac')
            ->withAnyParameters()
            ->will($this->returnValue('hmac'));
        return $mock;
    }
    private function getConfigurationManager()
    {
        return new ConfigurationManager('example.com', '/', null, 'key', 'salt');
    }

    private function getUserProviderMock()
    {
        $userProviderMock = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $userProviderMock->expects($this->any())
            ->method('loadUserByUsername')
            ->with('admin')
            ->will($this->returnValue($this->getUserMock()));

        return $userProviderMock;
    }

    private function getUserMock()
    {
        $userMock = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $userMock->expects($this->any())
            ->method('getUsername')
            ->will($this->returnValue('admin'));
        $userMock->expects($this->any())
            ->method('getPassword')
            ->will($this->returnValue('password'));
        $userMock->expects($this->any())
            ->method('getRoles')
            ->will($this->returnValue(['WP_SUBSCRIBER']));

        return $userMock;
    }
}
