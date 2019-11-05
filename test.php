<?php
ini_set("memory_limit", '2048M');

$rsa = new RsaUtil();
$pub = file_get_contents(__DIR__.'/szkingdom_pub.cer');
$pri = file_get_contents(__DIR__.'/szkingdom_pri.pfx');

var_dump($rsa->setPublicKey($pub));
var_dump($rsa->setPkcs12($pri, "12345678"));

// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());
// var_dump("getPublicKey", $rsa->getPublicKey());
// var_dump("getPrivateKey", $rsa->getPrivateKey());
// var_dump("getPkcs12", $rsa->getPkcs12());


$encryptedTemp = $rsa->encrypt("abckeddd");
var_dump("encrypted", $encryptedTemp);
$decryptedTemp = $rsa->decrypt($encryptedTemp);
var_dump("decrypted",$decryptedTemp);


// var_dump("split", $rsa->split("adc", 1));