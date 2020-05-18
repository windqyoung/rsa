<?php

namespace Wqy\Rsa\Tests;

use PHPUnit\Framework\TestCase;
use Wqy\Rsa\RsaPrivate;
use Wqy\Rsa\RsaPublic;

class RsaTest extends TestCase
{
    /**
     * @var RsaPublic
     */
    private $pub;
    /**
     * @var RsaPrivate
     */
    private $pri;

    public function setUp(): void
    {
        parent::setUp();

        $this->pub = new RsaPublic(file_get_contents(__DIR__ . '/resources/pub.pem'));
        $this->pri = new RsaPrivate(file_get_contents(__DIR__ . '/resources/pri.pem'));
    }

    public function testKeySetOk()
    {
        $this->assertNotFalse($this->pub->getKey());
        $this->assertNotFalse($this->pri->getKey());
    }
    
    private function getString($len)
    {
        $rt = random_bytes($len);
        return $rt;
    }

    public function testPrivateEncryptPublicDecrypt()
    {
        for ($i = 1; $i <= 5000; $i *= 2) {
            $data = $this->getString($i);
            $en = $this->pri->encrypt($data);
            $de = $this->pub->decrypt($en);
            $this->assertEquals($data, $de);
        }
    }

    public function testPrivateEncryptPublicDecryptBase64()
    {
        for ($i = 1; $i <= 5000; $i *= 2) {
            $data = $this->getString($i);
            $en = $this->pri->encryptBase64($data);
            $de = $this->pub->decryptBase64($en);
            $this->assertEquals($data, $de);
        }
    }

    public function testPublicEncryptPrivateDecrypt()
    {
        for ($i = 1; $i <= 5000; $i *= 2) {
            $data = $this->getString($i);
            $en = $this->pub->encrypt($data);
            $de = $this->pri->decrypt($en);
            $this->assertEquals($data, $de);
        }
    }

    public function testPublicEncryptPrivateDecryptBase64()
    {
        for ($i = 1; $i <= 5000; $i *= 2) {
            $data = $this->getString($i);
            $en = $this->pub->encryptBase64($data);
            $de = $this->pri->decryptBase64($en);
            $this->assertEquals($data, $de);
        }
    }

    public function testSignVerify()
    {
        for ($i = 1; $i <= 5000; $i *= 2) {
            $data = $this->getString($i);
            $sign = $this->pri->sign($data);
            $verifyRs = $this->pub->verify($data, $sign);
            $this->assertEquals($verifyRs, 1);
        }
    }


    public function testSignVerifyBase64()
    {
        for ($i = 1; $i <= 5000; $i *= 2) {
            $data = $this->getString($i);
            $sign = $this->pri->signBase64($data);
            $verifyRs = $this->pub->verifyBase64($data, $sign);
            $this->assertEquals($verifyRs, 1);
        }
    }
}