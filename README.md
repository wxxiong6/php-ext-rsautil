# php-ext-RSAUtil

[![Build Status](https://travis-ci.org/wxxiong6/php-ext-arraylist.svg?branch=master)](https://travis-ci.org/wxxiong6/php-ext-arraylist)

标准RSA算法，使用填充方式，能够处理超过128字节长度的数据。

## Requirement
php7.0 +

## Install

```shell
phpize
./configure --enable-rsautil
make 
make install
```
## Document
```php

RSAUtil
RSAUtil::setPublicKey(string $pub) : bool
RSAUtil::setP12(string $p12, string $pass) : bool
RSAUtil::publicEncrypt(string $data, mixed $pub) : string
RSAUtil::privateDecrypt(string $data, mixed $pri) : string
RSAUtil::privateEncrypt(string $data, mixed $pri) : string
RSAUtil::publicDecrypt(string $data, mixed $pub) : string

// @see https://www.php.net/manual/zh/openssl.signature-algos.php
// signature_alg
RSAUtil::sign(string $data,  mixed $pri, mixed $signature_alg) : string

//如果签名正确返回 1, 签名错误返回 0, 内部发生错误则返回-1.
RSAUtil::verify(string $data, string $signature, mixed $pub, mixed $signature_alg) :int
RSAUtil::getErrors():array
```
