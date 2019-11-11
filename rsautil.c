#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_var.h"
#include "php_rsautil.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE()  \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif



zend_class_entry rsautil_ce;
zend_class_entry *rsautil_ce_ptr;


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

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_public, 0, 0, 1)
	ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_pkcs12, 0, 0, 2)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_private, 0, 0, 1)
ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_sign, 0, 0, 2)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, signature_alg)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_verify, 0, 0, 3)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, signature)
	ZEND_ARG_INFO(0, signature_alg)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rsautil_void, 0)
ZEND_END_ARG_INFO()
/* }}} */


static void rsautil_get_property(char *name, size_t name_len, INTERNAL_FUNCTION_PARAMETERS)
{
	zval *res, rv;

	if (zend_parse_parameters_none() == FAILURE)
	{
		return;
	}
	res = zend_read_property(rsautil_ce_ptr, getThis(), name, name_len, 0, &rv);
	ZVAL_DEREF(res);
	ZVAL_COPY(return_value, res);
}

static zval*  get_key_source(const char *data, const char * fun_name)
{
	zval function_name, retval, params[1], *result = NULL;
	uint32_t param_count = 1;
	int fun_result;

	ZVAL_STRING(&function_name, fun_name);
	ZVAL_STRING(&params[0], data);

	fun_result =  call_user_function_ex(EG(function_table),
				NULL,
				&function_name,
				&retval,
				param_count, params,
				0, NULL);
	zval_ptr_dtor(&function_name);
	zval_ptr_dtor(&params[0]);
	if (SUCCESS != fun_result)
	{
		return NULL;
	}

	if (Z_TYPE(retval) == IS_RESOURCE)
	{
		result = &retval;
		php_debug_zval_dump(&retval, 1);
		php_debug_zval_dump(result, 1);
		zval_ptr_dtor(&retval);
		php_debug_zval_dump(result, 1);
	}

	
	return result;
}

static void rsautil_set_property(const char *name, size_t name_len, const char *data, const char *function_name, INTERNAL_FUNCTION_PARAMETERS)
{
	zval *retval = get_key_source(data, function_name);

	
	if (retval == NULL) 
	{
		php_error_docref(NULL, E_WARNING, "Failed to setPrivateKey in %s.", function_name);
		RETURN_FALSE;
	} else if (Z_TYPE_P(retval) == IS_RESOURCE) {
		zend_update_property(rsautil_ce_ptr, getThis(), name, name_len, retval);
		zval_ptr_dtor(retval);
		RETURN_TRUE;
	} else {
		php_error_docref(NULL, E_WARNING, "Failed to in %s.", function_name);
		RETURN_FALSE;
	}
}

static zval* get_pkcs12(const char *data, size_t data_len, const char *password, size_t password_len)
{
	zval function_name, retval, params[3], *pkcs12;
	uint32_t param_count = 3;
	int result;
	
	ZVAL_STRING(&function_name, RSA_PKCS12_READ);
	ZVAL_STRINGL(&params[0], data, data_len);
	ZVAL_NEW_REF(&params[1], &EG(uninitialized_zval));
	ZVAL_STRINGL(&params[2], password, password_len);

	result = call_user_function_ex(EG(function_table),
				NULL,
				&function_name,
				&retval,
				param_count, params,
				0, NULL);

	zval_ptr_dtor(&function_name);
	zval_ptr_dtor(&params[2]);
	zval_ptr_dtor(&params[0]);
				
	if (result != SUCCESS || Z_TYPE(retval) != IS_TRUE)
	{
		zval_ptr_dtor(&retval);
		return NULL;
	}

	if (Z_ISREF(params[1]) && Z_TYPE_P(Z_REFVAL(params[1])) == IS_ARRAY)
	{
		pkcs12 = Z_REFVAL(params[1]);
	}

	zval_ptr_dtor(&params[1]);
	zval_ptr_dtor(&retval);
	
	return pkcs12;
}

/**
 *	rsautil::setPrivateKey(string data, string password)
 */
PHP_METHOD(rsautil, setPkcs12)
{
	char *data;
	size_t data_len;
	char *password;
	size_t password_len;
	zval *pkcs12, *zv_pkey;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(data, data_len)
		Z_PARAM_STRING(password, password_len)
	ZEND_PARSE_PARAMETERS_END();

	pkcs12 = get_pkcs12(data, data_len, password, data_len);
	if (pkcs12 == NULL)
	{
		php_error_docref(NULL, E_WARNING, "Failed to setPkcs12");
		RETURN_FALSE;
	}

	zv_pkey = zend_hash_str_find(Z_ARR_P(pkcs12), ZEND_STRL("pkey"));
	if (zv_pkey && Z_TYPE_P(zv_pkey) == IS_STRING && Z_STRLEN_P(zv_pkey) > 0)
	{
		rsautil_set_property(ZEND_STRL(PROPERTY_PRIVATEKEY), Z_STRVAL_P(zv_pkey), "openssl_pkey_get_private", INTERNAL_FUNCTION_PARAM_PASSTHRU);	
	}
	else 
	{
		php_error_docref(NULL, E_WARNING, "Failed to pkey not in the pkcs12 file.");
		RETURN_FALSE;
	}
	
	RETURN_TRUE;
}
/* }}} */

/**	{{{ rsautil::setPrivateKey(data, password, crypted)
**/
PHP_METHOD(rsautil, setPrivateKey)
{
	char *data;
	size_t data_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(data, data_len)
	ZEND_PARSE_PARAMETERS_END();

	rsautil_set_property(ZEND_STRL(PROPERTY_PRIVATEKEY), data, "openssl_pkey_get_private", INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

PHP_METHOD(rsautil, setPublicKey)
{
	char *data;
	size_t data_len;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(data, data_len)
	ZEND_PARSE_PARAMETERS_END();

	rsautil_set_property(ZEND_STRL(PROPERTY_PUBLICKEY), data,  "openssl_pkey_get_public", INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

PHP_METHOD(rsautil, getPublicKey)
{
	rsautil_get_property(ZEND_STRL(PROPERTY_PUBLICKEY), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

PHP_METHOD(rsautil, getPrivateKey)
{
	rsautil_get_property(ZEND_STRL(PROPERTY_PRIVATEKEY), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

PHP_METHOD(rsautil, getPkcs12)
{
	rsautil_get_property(ZEND_STRL(PROPERTY_PKCS12), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}


/* {{{ rsautil_deps[] 扩展依赖
 */
#if ZEND_MODULE_API_NO >= 20050922
static const zend_module_dep rsautil_deps[] = {
	ZEND_MOD_REQUIRED("openssl")
	ZEND_MOD_END
};
#endif
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

	PHP_ME(rsautil, getPublicKey,  arginfo_rsautil_void,        ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPublicKey,  arginfo_rsautil_set_public,  ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPrivateKey, arginfo_rsautil_void,        ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPrivateKey, arginfo_rsautil_set_private, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPkcs12,     arginfo_rsautil_set_pkcs12,  ZEND_ACC_PUBLIC)
	// PHP_ME(rsautil, encrypt,       arginfo_rsautil_encrypt,     ZEND_ACC_PUBLIC)
	// PHP_ME(rsautil, decrypt,       arginfo_rsautil_decrypt,     ZEND_ACC_PUBLIC)
	// PHP_ME(rsautil, split,         arginfo_rsautil_void,        ZEND_ACC_PUBLIC)
	// PHP_ME(rsautil, sign,          arginfo_rsautil_sign,        ZEND_ACC_PUBLIC)
	// PHP_ME(rsautil, verify,        arginfo_rsautil_verify,      ZEND_ACC_PUBLIC)
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
	php_info_print_table_end();
}
/* }}} */

// 模块初始化时调用
PHP_MINIT_FUNCTION(rsautil) /* {{{ */
{
	//REGISTER_INI_ENTRIES(); // register ini
	INIT_CLASS_ENTRY(rsautil_ce, "RSAUtil", rsautil_methods); //注册类及类方法
	rsautil_ce_ptr = zend_register_internal_class(&rsautil_ce TSRMLS_CC);
	//set property
	zend_declare_property_null(rsautil_ce_ptr, ZEND_STRL(PROPERTY_PUBLICKEY), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(rsautil_ce_ptr, ZEND_STRL(PROPERTY_PRIVATEKEY), ZEND_ACC_PUBLIC TSRMLS_CC);
	zend_declare_property_null(rsautil_ce_ptr, ZEND_STRL(PROPERTY_PKCS12), ZEND_ACC_PUBLIC TSRMLS_CC);

	return SUCCESS;
}
/* }}} */

/* {{{ rsautil_module_entry
 */
zend_module_entry rsautil_module_entry = {
	#if ZEND_MODULE_API_NO >= 20050922
		STANDARD_MODULE_HEADER_EX, NULL,
		rsautil_deps,		 
	#else
		STANDARD_MODULE_HEADER,
	#endif
	"rsautil",			 /* Extension name */
	rsautil_functions,   /* zend_function_entry */
	PHP_MINIT(rsautil),  /* PHP_MINIT - Module initialization */
	NULL,				 /* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(rsautil),  /* PHP_RINIT - Request initialization */
	NULL,				 /* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(rsautil),  /* PHP_MINFO - Module info */
	PHP_RSAUTIL_VERSION, /* Version */
	STANDARD_MODULE_PROPERTIES
	};
/* }}} */

#ifdef COMPILE_DL_RSAUTIL
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(rsautil)
#endif
