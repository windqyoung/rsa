<?php


namespace Wqy\Rsa;

trait RsaTrait
{
    /**
     * @var false|resource
     */
    private $key;

    private $error_string;

    /**
     * @return false|resource
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param false|resource $key
     */
    public function setKey($key): void
    {
        $this->key = $key;
    }

    /**
     * @return mixed
     */
    public function getErrorString()
    {
        return $this->error_string;
    }

    /**
     * @param mixed $error_string
     */
    private function setErrorString($error_string)
    {
        $this->error_string = $error_string;
    }

    /**
     * 分块执行方法
     * @param string $data
     * @param int $blockSize
     * @param callable $cb
     * @return bool|string false 执行失败
     */
    private function chunkRsa($data, $blockSize, $cb)
    {
        if ($blockSize <= 0) {
            $this->setErrorString('块大小不能设为0');
            return false;
        }

        $rt = '';
        for ($i = 0, $len = strlen($data); $i < $len; $i += $blockSize) {
            $block = substr($data, $i, $blockSize);
            $rs = $cb($block);
            if (false === $rs) {
                return false;
            }
            $rt .= $rs;
        }
        return $rt;
    }

    /**
     * @param resource $key
     * @return int
     */
    private function getKeyBits()
    {
        $detail = openssl_pkey_get_details($this->key);
        return $detail['bits'];
    }

    /**
     * @param string $data
     * @return string 加密, 然后返回base64格式
     */
    public function encryptBase64($data)
    {
        return base64_encode($this->encrypt($data));
    }

    /**
     * @param string $base64Data
     * @return mixed
     */
    public function decryptBase64($base64Data)
    {
        return $this->decrypt(base64_decode($base64Data));
    }
}