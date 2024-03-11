<?php

class GenerateToken
{
    private $clientId      = 'XXXXXX';

    private $clientSecret = 'XXXXXX';

    //Get Token
    public function createToken() {
        try {

            $credentials = base64_encode(self::$clientId . ':' . self::$clientSecret);

            $headers = array(
                'Content-Type:application/x-www-form-urlencoded',
                'Authorization: Basic '. $credentials//
            );

            $url = "https://Your_Url.auth.ap-northeast-1.amazoncognito.com/oauth2/token";
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);   
            curl_setopt($ch,CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch,CURLOPT_POSTFIELDS, "grant_type=client_credentials&scope=client.credential/all-access");
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); 
            $responseJson = curl_exec($ch);
            curl_close($ch);
            $response = json_decode($responseJson);

            return $response->access_token;

        } catch (AwsException $e) {
            // Handle any errors
            echo 'Error: ' . $e->getMessage();
        }
    }

}
