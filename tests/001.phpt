--TEST--
Check for RSAUtil load
--SKIPIF--
<?php if (!extension_loaded("rsautil")) print "skip"; ?>
--FILE--
<?php 
echo "rsautil extension is available";
?>
--EXPECT--
rsautil extension is available