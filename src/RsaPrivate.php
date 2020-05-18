<?php

namespace Wqy\Rsa;

/**
 * 使用rsa私钥加解密
 */
class RsaPrivate
{
    use RsaTrait;

    /**
     * @var false|resource
     */
    private $key;

    /**
     * @param $key string
     */
    public function __construct($key)
    {
        $this->setKey(openssl_pkey_get_private($key));
    }


    /**
     * @param string $data 加密
     * @return bool|string false 加密失败
     */
    public function encrypt($data)
    {
        // 加密, 块大小为 bits / 8 - 11
        $blockSize = $this->getKeyBits() / 8 - 11;
        // 需要分块
        return $this->chunkRsa($data, $blockSize, function ($blockData) {
            $enRs = openssl_private_encrypt($blockData, $encrypted, $this->key);

            // 加密失败
            if (! $enRs) {
                $this->setErrorString(openssl_error_string());
                return false;
            }

            return $encrypted;
        });
    }

    public function decrypt($data)
    {
        // 解密, 块大小为 bits / 8
        $blockSize = $this->getKeyBits() / 8;
        return $this->chunkRsa($data, $blockSize, function ($blockData) {
            $deRs = openssl_private_decrypt($blockData, $decrypted, $this->key);

            // 解密失败
            if (! $deRs) {
                $this->setErrorString(openssl_error_string());
                return false;
            }
            return $decrypted;
        });
    }

    /**
     * 使用私钥对数据签名
     * @param string $data
     * @param int $signature_alg
     * @return bool|string false: 签名失败
     */
    public function sign($data, $signature_alg = OPENSSL_ALGO_SHA256)
    {
        $rs = openssl_sign($data, $signature, $this->key, $signature_alg);
        // 签名失败
        if (! $rs) {
            $this->setErrorString(openssl_error_string());
            return false;
        }
        return $signature;
    }


    public function signBase64($data, $signature_alg = OPENSSL_ALGO_SHA256)
    {
        $sign = $this->sign($data, $signature_alg);
        return $sign === false ? false : base64_encode($sign);
    }
}