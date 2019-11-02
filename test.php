<?php
$Rsa = new RsaUtil();
$pub = file_get_contents(__DIR__.'/szkingdom_pub.cer');
$pri = file_get_contents(__DIR__.'/szkingdom_pri.pfx');
// var_dump($Rsa->getPublicKey($pub));
// var_dump(openssl_pkey_get_public($pub));

var_dump($Rsa->setPublicKey($pub));
var_dump($Rsa->setPrivateKey($pri, "12345678"));
//var_dump($Rsa->getPublicKey());
// var_dump($Rsa->getPrivateKey());
//$encryptedTemp = '';
//var_dump($Rsa->encrypt("ABDC", $encryptedTemp, $Rsa->getPublicKey(), OPENSSL_PKCS1_PADDING));
// var_dump($Rsa);
// openssl_public_encrypt("123131233", $encryptedTemp, $Rsa->getPublicKey(), OPENSSL_PKCS1_PADDING);

// openssl_public_encrypt("ABCD", $encryptedTemp, $Rsa->getPublicKey("33"), OPENSSL_PKCS1_PADDING);

// var_dump($encryptedTemp);