--TEST--
Check for iteration of RSAUtil class
--SKIPIF--
<?php if (!extension_loaded("rsautil")) print "skip"; ?>
--FILE--
<?php 
$str = "公钥加密私钥解密吼吼！";
$str2 = "私钥加密公钥解密哈哈！";
$pub = file_get_contents(__DIR__.'/rsa_public_key.pem');
$pri = file_get_contents(__DIR__.'/rsa_private_key.pem');
for($i = 0; $i < 15; $i++) {
    $rsa = new RSAUtil();
    $rsa->setPublicKey($pub);
    $rsa->setPrivateKey($pri);
    $encrypted = $rsa->publicEncrypt($str);
    $decrypted = $rsa->privateDecrypt($encrypted);
    $sign = $rsa->sign($encrypted, OPENSSL_ALGO_MD5);
    $verify = $rsa->verify($encrypted, $sign, OPENSSL_ALGO_MD5);


    $encrypted2 = $rsa->privateEncrypt($str2);
    $decrypted2 = $rsa->publicDecrypt($encrypted2);
}
var_dump($rsa->setPublicKey($pub));
var_dump($rsa->setPrivateKey($pri));
var_dump((bool)$rsa->setPrivateKey($pri));
var_dump((bool)$rsa->getPrivateKey());

$encrypted = $rsa->publicEncrypt($str);
$decrypted = $rsa->privateDecrypt($encrypted);
var_dump($str === $decrypted);

$sign = $rsa->sign($encrypted, OPENSSL_ALGO_MD5);
$verify = $rsa->verify($encrypted, $sign, OPENSSL_ALGO_MD5);
var_dump($verify === 1);


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