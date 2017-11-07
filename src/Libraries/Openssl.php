<?php
namespace Mula\Libraries;

class Openssl
{
    /**
     * Merchant's IV key
     */
    private $iv;

    /**
     * Merchant's secret key
     */
    private $key;

    /**
     * Openssl constructor.
     *
     * @param $iv_key
     * @param $secret_key
     */
    public function __construct($iv_key, $secret_key)
    {
        $this->iv = $iv_key;
        $this->key = $secret_key;
    }


    /**
     * Encrypt the string of customer details with the IV and secret key.
     *
     * @param array|string $payload string Pass in the array of parameters to be pass to express checkout.
     * @return string
     */
    public function encryptData($payload = [])
    {
        //The encryption method to be used
        $encrypt_method = "AES-256-CBC";

        // Hash the secret key
        $key = hash('sha256', $this->key);

        // Hash the iv - encrypt method AES-256-CBC expects 16 bytes
        $iv = substr(hash('sha256', $this->iv), 0, 16);

        $encrypted = openssl_encrypt(
            json_encode($payload, true),
            $encrypt_method,
            $key,
            0,
            $iv
        );

        //Base 64 Encode the encrypted payload
        $encrypted = base64_encode($encrypted);

        return $encrypted;
    }

    /**
     * Decrypt the encrypted code from the express checkout
     * of the response payload on completion on the express checkout.
     *
     * @param $payload
     * @return string
     */
    public function decryptPayload($payload)
    {
        $encrypt_method = 'AES-256-CBC';

        // Hash secret key
        $key = hash('sha256', $this->key);

        // Hash iv - encrypt method AES-256-CBC expects 16 bytes
        $iv = substr(hash('sha256',  $this->iv), 0, 16);

        $decrypted = openssl_decrypt(
            base64_decode($payload),
            $encrypt_method,
            $key,
            0,
            $iv
        );

        return $decrypted;
    }
}