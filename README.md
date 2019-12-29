# php-ext-RSAUtil

[![Build Status](https://travis-ci.org/wxxiong6/php-ext-rsautil.svg?branch=master)](https://travis-ci.org/wxxiong6/php-ext-rsautil.svg?branch=master)

这个扩展是RSA算法工具类，面向对象方式封装。使用方法简单快捷高效。可以兼容java的RSA。支持超过128个字符的数据加解密。

## Requirement
- php7.0 +
- OpenSSL Extension

## Install

```shell
phpize
./configure --enable-rsautil
make 
make install
```
## Document
```php
RsaUtil::setPublicKey(string $pub) : bool
RsaUtil::setP12(string $p12, string $pass) : bool
RsaUtil::publicEncrypt(string $data, mixed $pub) : string
RsaUtil::privateDecrypt(string $data, mixed $pri) : string
RsaUtil::privateEncrypt(string $data, mixed $pri) : string
RsaUtil::publicDecrypt(string $data, mixed $pub) : string

// @see https://www.php.net/manual/zh/openssl.signature-algos.php
// signature_alg
RsaUtil::sign(string $data,  mixed $pri, mixed $signature_alg) : string

//如果签名正确返回 1, 签名错误返回 0, 内部发生错误则返回-1.
RsaUtil::verify(string $data, string $signature, mixed $pub, mixed $signature_alg) :int
RsaUtil::getErrors():array
```
