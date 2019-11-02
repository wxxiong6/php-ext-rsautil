/* rsautil extension for PHP */

#ifndef PHP_RSAUTIL_H
# define PHP_RSAUTIL_H

extern zend_module_entry rsautil_module_entry;
# define phpext_rsautil_ptr &rsautil_module_entry

# define PHP_RSAUTIL_VERSION "0.1.0"

# if defined(ZTS) && defined(COMPILE_DL_RSAUTIL)
ZEND_TSRMLS_CACHE_EXTERN()
# endif
PHP_MINIT_FUNCTION(rsautil);
#endif	/* PHP_RSAUTIL_H */

