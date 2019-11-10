# php-ext-RSAUtil
php扩展RSAUtil

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
RSAUtil::setPublicKey()
RSAUtil::setPkcs12()
RSAUtil::encrypt()
RSAUtil::decrypt()
RSAUtil::sign()
RSAUtil::verify()
```
