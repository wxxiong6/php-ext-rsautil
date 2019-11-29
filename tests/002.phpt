--TEST--
Check for all method of RSAUtil class
--SKIPIF--
<?php if (!extension_loaded("rsautil")) print "skip"; ?>
--FILE--
<?php 
$rsa = new RSAUtil();
$pub = file_get_contents(__DIR__.'/rsa_public_key.pem');
$pri = file_get_contents(__DIR__.'/rsa_private_key.pem');
var_dump($rsa->setPublicKey($pub));
var_dump($rsa->setPrivateKey($pri));
var_dump((bool)$rsa->getPublicKey());
var_dump((bool)$rsa->getPrivateKey());
$str = "公钥加密私钥解密吼吼！";
$encrypted = $rsa->publicEncrypt($str);
$decrypted = $rsa->privateDecrypt($encrypted);
var_dump($str === $decrypted);

$sign = $rsa->sign($encrypted, OPENSSL_ALGO_MD5);
$verify = $rsa->verify($encrypted, $sign, OPENSSL_ALGO_MD5);
var_dump($verify === 1);

$str2 = "私钥加密公钥解密哈哈！";
$encrypted2 = $rsa->privateEncrypt($str2);
$decrypted2 = $rsa->publicDecrypt($encrypted2);
var_dump($str2 === $decrypted2);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)