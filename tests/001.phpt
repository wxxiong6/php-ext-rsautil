--TEST--
Check for RSAUtil load
--SKIPIF--
<?php if (!extension_loaded("rsautil")) print "skip"; ?>
--FILE--
<?php 
$rsa = new RSAUtil();
print_r($rsa);
?>
--EXPECT--
RSAUtil Object
(
    [publicKey] => 
    [privateKey] => 
    [pkcs12] => 
)