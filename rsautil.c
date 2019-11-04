/* rsautil extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_var.h"
#include "ext/standard/base64.h"
#include "php_rsautil.h"



/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

//类实体
zend_class_entry *rsautil_ce_ptr;
zend_class_entry rsautil_ce;

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(rsautil)
{
#if defined(ZTS) && defined(COMPILE_DL_RSAUTIL)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */





/* {{{ arginfo
 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_encrypt, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_decrypt, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO(arginfo_rsautil_set_public, 0)
	ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_setPkcs12, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_private, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()


ZEND_BEGIN_ARG_INFO(arginfo_rsautil_void, 0)
ZEND_END_ARG_INFO()
/* }}} */



static zval getKey(zend_string *data) {
	zval function_name, retval, callback_params[1];
	uint32_t call_func_param_cnt = 1;
	ZVAL_STRING(&function_name, "openssl_pkey_get_public");

	ZVAL_STR_COPY(&callback_params[0], data);
    //call
    if(SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params TSRMLS_CC)){
        ZVAL_FALSE(&retval);
    }   
	zval_dtor(&callback_params[0]);
	return retval;
}


PHP_METHOD(rsautil, setPkcs12) {
	zend_string *data, *password, *crypted;
	zval   result;
	
	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(data)
		Z_PARAM_STR(password)
	ZEND_PARSE_PARAMETERS_END();


	const uint32_t MAX_PARAMS = 3;
	zval function_name, retval, callback_params[MAX_PARAMS];

	uint32_t call_func_param_cnt = MAX_PARAMS;
	
	ZVAL_STRING(&function_name, "openssl_pkcs12_read");
	ZVAL_STR_COPY(&callback_params[0], data);
	ZVAL_NEW_EMPTY_REF(&callback_params[1]);
	ZVAL_STR_COPY(&callback_params[2], password);
	
    if(SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params TSRMLS_CC)){
      RETURN_FALSE;
    }

	zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PKCS12), Z_REFVAL_P(&callback_params[1]) TSRMLS_CC);	
	zend_array *zarr;
	zarr = Z_ARR_P(Z_REFVAL_P(&callback_params[1]));

	zval *zv = zend_hash_str_find(zarr, ZEND_STRL("pkey"));
	if (zv) {
		zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), zv TSRMLS_CC);
		ZVAL_DEREF(zv);
	} else {
		php_error_docref(NULL, E_WARNING, "Failed to privatekey");
		RETURN_FALSE;
	}
	zval_dtor(zv);
	zval_dtor(&callback_params[1]);
	RETURN_TRUE;
}


/**
$Rsa->setPrivateKey(data, password, crypted)
**/
PHP_METHOD(rsautil, setPrivateKey) {
	zval *data;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_ZVAL(data)
	ZEND_PARSE_PARAMETERS_END();
	zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), data TSRMLS_CC);
	zval_dtor(data);
	RETURN_TRUE;
}


PHP_METHOD(rsautil, setPublicKey) {
	zend_string *data;
	zval retval;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();
	retval = getKey(data);
	zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), &retval TSRMLS_CC);
    zval_dtor(&retval);
	RETURN_TRUE;
}

PHP_METHOD(rsautil, getPublicKey) {
	zval *key;
	key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 TSRMLS_DC, NULL);
	zval_ptr_dtor(key);
	RETURN_RES(Z_RES_P(key));
}

PHP_METHOD(rsautil, getPrivateKey) {
	zval   *key;
	key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 TSRMLS_DC, NULL);
	zval_ptr_dtor(key);
	RETURN_STR(Z_STR_P(key));
}

PHP_METHOD(rsautil, getPkcs12) {
	zval  *key;
	key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PKCS12), 1 TSRMLS_DC, NULL);
	zval_ptr_dtor(key);
	RETURN_ARR(Z_ARR_P(key));
}

PHP_METHOD(rsautil, decrypt)
{
	
	zend_long padding = 1;
	char * data;
	size_t data_len;
	zend_string *base64_str = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(data, data_len)
	ZEND_PARSE_PARAMETERS_END();

	zval  rv, *privateKey;
	privateKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 TSRMLS_DC, &rv);
	if (!privateKey) {
		php_error_docref(NULL, E_WARNING, "Failed to privateKey ");
		RETURN_FALSE;
	}
	zval_dtor(&rv);
	base64_str = php_base64_decode((unsigned char*) data, data_len);
	if (!base64_str) {
			php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
			RETURN_FALSE;
	}

	zval callback_params[4];
	ZVAL_STR_COPY(&callback_params[0], base64_str);
	ZVAL_NEW_EMPTY_REF(&callback_params[1]);
	ZVAL_STR_COPY(&callback_params[2], Z_STR_P(privateKey));
	ZVAL_LONG(&callback_params[3], padding)
	
	zval function_name, retval;
	uint32_t call_func_param_cnt = 4;
	ZVAL_STRING(&function_name, "openssl_private_decrypt");

	zval_dtor(privateKey);

    if(SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval , call_func_param_cnt, callback_params)){
        RETURN_FALSE;
    }   
	RETURN_STR(Z_STR_P(Z_REFVAL_P(&callback_params[1])));
}

/* {{{ void rsautil::encrypt()
 */
PHP_METHOD(rsautil, encrypt)
{
	zend_long padding = 1;
	char * data;
	size_t data_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(data, data_len)
	ZEND_PARSE_PARAMETERS_END();


	zval *pulbicKey;

	pulbicKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 TSRMLS_DC, NULL);
	if (!pulbicKey) {
		php_error_docref(NULL, E_WARNING, "Failed to pulbicKey ");
		RETURN_FALSE;
	}
	zval_dtor(&rv);


	zval   callback_params[4];
	ZVAL_STRING(&callback_params[0], data);
	ZVAL_NEW_EMPTY_REF(&callback_params[1]);
	ZVAL_RES(&callback_params[2], Z_RES_P(pulbicKey));
	ZVAL_LONG(&callback_params[3], padding);
	
	// php_var_dump(&callback_params[1], 1);
	zval function_name, retval;
	uint32_t call_func_param_cnt = 4;
	ZVAL_STRING(&function_name, "openssl_public_encrypt");
    if(SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval , call_func_param_cnt, callback_params)){
        RETURN_FALSE;
    }   
	zval_dtor(pulbicKey);
	RETURN_STR(php_base64_encode((unsigned char*)Z_STRVAL_P(Z_REFVAL_P(&callback_params[1])), Z_STRLEN_P(Z_REFVAL_P(&callback_params[1]))));
}
/* }}} */


/* {{{ rsautil_deps[] 扩展依赖
 */
static const  zend_module_dep rsautil_deps[] = {
    ZEND_MOD_REQUIRED("openssl")
    ZEND_MOD_END
};
/* }}} */

/* {{{ rsautil_functions[]
 */
static const zend_function_entry rsautil_functions[] = {
	PHP_FE_END
};
/* }}} */

/* {{{ rsautil_methods[] 扩展类方法
 */
static const zend_function_entry rsautil_methods[] = { 
	PHP_ME(rsautil, encrypt, arginfo_rsautil_encrypt, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPublicKey, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPublicKey, arginfo_rsautil_set_public, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPrivateKey, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPrivateKey, arginfo_rsautil_set_private, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPkcs12, arginfo_rsautil_set_setPkcs12, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPkcs12, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, decrypt, arginfo_rsautil_decrypt, ZEND_ACC_PUBLIC)
	PHP_FE_END
};
/* }}} */


/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(rsautil)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "rsautil support", "enabled");
	php_info_print_table_row(2, "Version", PHP_RSAUTIL_VERSION);
	php_info_print_table_row(2, "Author", "wxxiong6@gmail.com");
	php_info_print_table_row(2, "SSL Version", "OPENSSL");
	
	php_info_print_table_end();
}
/* }}} */

// 模块初始化时调用
PHP_MINIT_FUNCTION(rsautil) /* {{{ */ {
	//REGISTER_INI_ENTRIES(); // 注册ini
	INIT_CLASS_ENTRY(rsautil_ce, "RSAUtil", rsautil_methods); //注册类及类方法
    rsautil_ce_ptr = zend_register_internal_class(&rsautil_ce TSRMLS_CC);
	//添加属性
	zend_declare_property_null(rsautil_ce_ptr, ZEND_STRL(PROPERTY_PUBLICKEY), ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(rsautil_ce_ptr, ZEND_STRL(PROPERTY_PRIVATEKEY), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(rsautil_ce_ptr, ZEND_STRL(PROPERTY_PKCS12), ZEND_ACC_PUBLIC TSRMLS_CC);

    return SUCCESS;
}
/* }}} */


/* {{{ rsautil_module_entry
 */
zend_module_entry rsautil_module_entry = {
	STANDARD_MODULE_HEADER_EX, NULL,
	rsautil_deps,               //依赖
	"rsautil",					/* Extension name */
	rsautil_functions,			/* zend_function_entry */
	PHP_MINIT(rsautil),			/* PHP_MINIT - Module initialization */
	NULL,						/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(rsautil),			/* PHP_RINIT - Request initialization */
	NULL,						/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(rsautil),			/* PHP_MINFO - Module info */
	PHP_RSAUTIL_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */


#ifdef COMPILE_DL_RSAUTIL
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(rsautil)
#endif

