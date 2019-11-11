#ifndef PHP_RSAUTIL_H
# define PHP_RSAUTIL_H

extern zend_module_entry rsautil_module_entry;
#define phpext_rsautil_ptr &rsautil_module_entry

#define PHP_RSAUTIL_VERSION "1.0.0"


#define PROPERTY_PUBLICKEY   "publicKey"
#define PROPERTY_PRIVATEKEY  "privateKey"
#define PROPERTY_PKCS12      "pkcs12"

/* names of methods */
#define RSA_PKCS12_READ		"openssl_pkcs12_read"
// #define rsa_pkcs12_read		"stream_open"
// #define rsa_pkcs12_read		"stream_open"
// #define rsa_pkcs12_read		"stream_open"


PHP_MINIT_FUNCTION(rsautil);




#if defined(ZTS) && defined(COMPILE_DL_RSAUTIL)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

#endif
