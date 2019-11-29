<?php

$rsa = new RSAUtil();
$pub = file_get_contents(__DIR__.'/tests/rsa_public_key.pem');
$pri = file_get_contents(__DIR__.'/tests/rsa_private_key.pem');

var_dump($rsa->setPublicKey($pub));
var_dump($rsa->setPrivateKey($pri));

var_dump("getPublicKey",         $rsa->getPublicKey());
debug_zval_dump("getPrivateKey", $rsa->getPrivateKey());

echo "------------------", "私钥加密公钥解密", "---------------------", " \n";
$encryptedTemp = $rsa->publicEncrypt("公钥加密私钥解密吼吼！");
var_dump("encrypted", $encryptedTemp);
$decryptedTemp = $rsa->privateDecrypt($encryptedTemp);
var_dump("decrypted", $decryptedTemp);

$sign = $rsa->sign($encryptedTemp, OPENSSL_ALGO_MD5);
var_dump("sign", $sign);


echo "------------------", "私钥加密公钥解密", "---------------------", " \n";
$encryptedTemp1 = $rsa->privateEncrypt("私钥加密公钥解密哈哈！");
var_dump("encrypted", $encryptedTemp1);
$decryptedTemp1 = $rsa->publicDecrypt($encryptedTemp1);
var_dump("decrypted", $decryptedTemp1);


$verify = $rsa->verify($encryptedTemp, $sign, OPENSSL_ALGO_MD5);
var_dump("verify", $verify);