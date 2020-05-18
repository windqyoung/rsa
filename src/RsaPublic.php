<?php

namespace Wqy\Rsa;

/**
 * 使用rsa公钥加解密
 */
class RsaPublic
{
    use RsaTrait;

    /**
     * @param $key string
     */
    public function __construct($key)
    {
        $this->setKey(openssl_pkey_get_public($key));
    }


    /**
     * @param string $data 加密
     * @return bool|string false 失败
     */
    public function encrypt($data)
    {
        // 加密, 块大小为 bits / 8 - 11
        $blockSize = $this->getKeyBits() / 8 - 11;
        // 需要分块
        return $this->chunkRsa($data, $blockSize, function ($blockData) {
            $enRs = openssl_public_encrypt($blockData, $encrypted, $this->key);

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
        // 如果是2048位, 按256字节分块
        return $this->chunkRsa($data, $blockSize, function ($blockData) {
            $deRs = openssl_public_decrypt($blockData, $decrypted, $this->key);
            // 解密失败
            if (! $deRs) {
                $this->setErrorString(openssl_error_string());
                return false;
            }
            return $decrypted;
        });
    }

    /**
     * @param string $data
     * @param string $signature
     * @param int $signature_alg
     * @return int 如果签名正确返回 1, 签名错误返回 0, 内部发生错误则返回-1.
     */
    public function verify($data, $signature, $signature_alg = OPENSSL_ALGO_SHA256)
    {
        return openssl_verify($data, $signature, $this->key, $signature_alg);
    }

    /**
     * @param string $data
     * @param string $base64Signature
     * @param int $signature_alg
     * @return int
     */
    public function verifyBase64($data, $base64Signature, $signature_alg = OPENSSL_ALGO_SHA256)
    {
        return $this->verify($data, base64_decode($base64Signature, $signature_alg));
    }
}