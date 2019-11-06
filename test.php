<?php
$rsa = new RsaUtil();
$pub = file_get_contents(__DIR__.'/szkingdom_pub.cer');
$pri = file_get_contents(__DIR__.'/szkingdom_pri.pfx');

var_dump($rsa->setPublicKey($pub));
var_dump($rsa->setPkcs12($pri, "12345678"));

var_dump("getPublicKey", $rsa->getPublicKey());
var_dump("getPrivateKey", $rsa->getPrivateKey());


$encryptedTemp = $rsa->encrypt("AAAAAA");
var_dump("encrypted", $encryptedTemp);
$decryptedTemp = $rsa->decrypt($encryptedTemp);
var_dump("decrypted", $decryptedTemp);
$sign = $rsa->sign("abc", 2);
var_dump("sign", $sign, 2);
$verify = $rsa->verify("abc", $sign, 2);
var_dump("verify", $verify);

// var_dump("split", $rsa->split("adc", 1));
