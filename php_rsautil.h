/* rsautil extension for PHP */

#ifndef PHP_RSAUTIL_H
# define PHP_RSAUTIL_H

extern zend_module_entry rsautil_module_entry;
# define phpext_rsautil_ptr &rsautil_module_entry

# define PHP_RSAUTIL_VERSION "1.0.0"


# define PROPERTY_PUBLICKEY   "publicKey"
# define PROPERTY_PRIVATEKEY  "privateKey"
# define PROPERTY_PKCS12      "pkcs12"

PHP_MINIT_FUNCTION(rsautil);


# if defined(ZTS) && defined(COMPILE_DL_RSAUTIL)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_RSAUTIL_H */

