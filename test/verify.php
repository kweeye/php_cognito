<?php
    $token = "XXXXXXXXXXXXXX";

    $verify_token = New VerifyToken();

    echo $verify_token->verifyToken($token);
?>