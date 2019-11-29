# php-ext-RSAUtil
php扩展RSAUtil
标准RSA算法,支持超过128字节长度的数据


## linux mac 环境下编译安装
```shell
phpize
./configure --enable-rsautil
make 
make install
```

支持方法
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

```
