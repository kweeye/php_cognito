<?php

require_once DATA_REALDIR . 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;

class VerifyToken {

    public function verifyToken(string $jwt)
    {
        try {
            $publicKey = null;
            $kid = $this->getKid($jwt);
            
            if ($kid) {
                $publicKey = $this->getPublicKey($kid);
            }

            if ($publicKey) {
             
                $result = JWT::decode($jwt, new Key($publicKey, 'RS256'));
                
                if ($result) {
                    return true;
                }
            }

            return false;
        } catch (AwsException $e) {
            // Handle any errors
            echo 'Error: ' . $e->getMessage();
        }
    }

    public function getKid(string $jwt): ?string
    {
        $tks = explode('.', $jwt);
   
        if (count($tks) === 3) {
            $header =  JWT::jsonDecode(JWT::urlsafeB64Decode($tks[0]));
            if ( isset($header->kid) ) {
                return $header->kid;
            }
        }

        return null;
    }

    private function getPublicKey(string $kid): ?string
    {
        $jwksUrl =  'https://cognito-idp.Your_Region.amazonaws.com/Your_User_Pool_Id.well-known/jwks.json';
        $ch = curl_init($jwksUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 3,
        ]);
        $jwks = curl_exec($ch);
        curl_close($ch);
        if ($jwks) {
            $json = json_decode($jwks, false);
            if ($json && isset($json->keys) && 
            is_array($json->keys)) {
                foreach ($json->keys as $jwk) {
                    if ($jwk->kid === $kid) {
                        return $this->jwkToPem($jwk);
                        
                    }
                }
            }
        }

        return null;
    }

    private function jwkToPem(object $jwk): ?string
    {
        if (isset($jwk->n) && isset($jwk->n)) {
            $rsa = PublicKeyLoader::load([
            'e' => new BigInteger(
                JWT::urlsafeB64Decode($jwk->e), 256),
            'n' => new BigInteger(
                JWT::urlsafeB64Decode($jwk->n),  256)
            ]);
            return $rsa;
        }

        return null;
    }
}