#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_var.h"
#include "ext/standard/base64.h"
#include "php_rsautil.h"
#include "zend_smart_str.h"


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

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_split, 0, 0, 2)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, split_length)
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

PHP_METHOD(rsautil, split)
{
	
}


static void rsautil_get_property(char *name, size_t name_len, INTERNAL_FUNCTION_PARAMETERS)
{
	zval *res;

	if (zend_parse_parameters_none() == FAILURE)
	{
		return;
	}
	res = zend_read_property(rsautil_ce_ptr, getThis(), name, name_len, 1, NULL);
	RETURN_ZVAL(res, 0, 0);
}

static void rsautil_set_property(char *name, size_t name_len, INTERNAL_FUNCTION_PARAMETERS)
{
	zend_string *arg;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(arg)
	ZEND_PARSE_PARAMETERS_END();

	zend_update_property_string(rsautil_ce_ptr, getThis(), name, name_len, ZSTR_VAL(arg));
}

static zval get_key_source(zend_string *data, char * fun_name)
{
	zval function_name, retval, params[1];
	uint32_t param_cnt = 1;
	ZVAL_STRING(&function_name, fun_name);

	ZVAL_STR_COPY(&params[0], data);
	//call
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, param_cnt, params TSRMLS_CC))
	{
		ZVAL_FALSE(&retval);
	}
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&function_name);
	return retval;
}

PHP_METHOD(rsautil, setPkcs12)
{
	char *data, *password;
	size_t data_len, password_len;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(data, data_len)
		Z_PARAM_STRING(password, password_len)
	ZEND_PARSE_PARAMETERS_END();

	zval function_name, retval, params[3];
	uint32_t param_cnt = 3;

	ZVAL_STRING(&function_name, "openssl_pkcs12_read");
	ZVAL_STRINGL(&params[0], data, data_len);
	ZVAL_NEW_REF(&params[1], &EG(uninitialized_zval));
	ZVAL_STRINGL(&params[2], password, password_len);

	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, param_cnt, params TSRMLS_CC))
	{
		php_error_docref(NULL, E_WARNING, "Failed to pkcs12_read.");
		RETURN_FALSE;
	}
	
	if (zval_get_long(&retval) == FAILURE) {
		php_error_docref(NULL, E_WARNING, "Failed to pkcs12_read Return false.");
		RETURN_FALSE;
	}
	zval_ptr_dtor(&function_name);
	zval_ptr_dtor(&params[0]);
	zval_ptr_dtor(&params[2]);
	zval *pkcs12 = NULL;

	if (Z_ISREF(params[1]) && Z_TYPE_P(Z_REFVAL(params[1])) == IS_ARRAY) {
		pkcs12 = Z_REFVAL(params[1]);
	}

	if (pkcs12 == NULL) {
		php_error_docref(NULL, E_WARNING, "Failed to pkcs12_read Return NULL.");
		RETURN_FALSE;
	}
	zend_array *zarr;
	zarr = Z_ARR_P(pkcs12);
	zval *zv_pkey = zend_hash_str_find(zarr, ZEND_STRL("pkey"));
	if (zv_pkey && Z_TYPE_P(zv_pkey) && Z_STRLEN_P(zv_pkey) > 0)
	{
		zval retval2;
		retval2 = get_key_source(Z_STR_P(zv_pkey), "openssl_pkey_get_private");
		zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), &retval2);
		Z_TRY_ADDREF(retval2);
		
	}
	zval_ptr_dtor(zv_pkey);
	ZVAL_UNREF(&params[1]);
	zval_ptr_dtor(&params[1]);
	RETURN_TRUE;
}

/**
$rsa->setprivate_key(data, password, crypted)
**/
PHP_METHOD(rsautil, setPrivateKey)
{
	zend_string *data;
	zval retval;
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();
	retval = get_key_source(data, "openssl_pkey_get_private");
	zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), &retval);
	Z_TRY_ADDREF(retval);
	RETURN_TRUE;
}

PHP_METHOD(rsautil, setPublicKey)
{
	zend_string *data;
	zval retval;
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();
	retval = get_key_source(data, "openssl_pkey_get_public");
	zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), &retval TSRMLS_CC);
	Z_TRY_ADDREF(retval);
	RETURN_TRUE;
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

static int call_funcion_with_param4(char *data, size_t data_len, char *func_name, zend_long padding, zval *key, char **str, int *str_len)
{	
	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;
	zval function_name, retval, params[4];
	int param_cnt = 4;

	ZVAL_STRINGL(&params[0], data, data_len);
	ZVAL_NEW_REF(&params[1],    &EG(uninitialized_zval));
	ZVAL_RES(&params[2],        Z_RES_P(key));
	ZVAL_LONG(&params[3],       padding);	
	ZVAL_STRING(&function_name, func_name);

	if (FAILURE == zend_fcall_info_init(&function_name, 0, &fci, &fci_cache, NULL, NULL)) {
		zval_dtor(&params[0]);
		zval_dtor(&params[1]);
		zval_dtor(&params[2]);
		zval_dtor(&params[3]);
		zval_dtor(&function_name);
		return FAILURE;
	}

	
	fci.param_count = param_cnt;
	fci.params = params;
	fci.retval = &retval;
	
	int result = zend_call_function(&fci, &fci_cache);

	zval_dtor(&params[0]);
	zval_dtor(&params[2]);
	zval_dtor(&params[3]);
	zval_dtor(&function_name);

	if (result != SUCCESS || Z_TYPE(retval) != IS_TRUE) 
	{
		zval_dtor(&retval);
		zval_dtor(&params[1]);
		php_error_docref(NULL, E_WARNING, "Failed to %s result=%d retval=%d len=%ld. ", func_name, result, Z_TYPE(retval), data_len);
		return FAILURE;
	}	

	if (Z_ISREF(retval)) {
		zend_unwrap_reference(&retval);
	}

	if (Z_ISREF(params[1])) {
		zend_unwrap_reference(&params[1]);
	}

	memcpy(*str, Z_STRVAL(params[1]), Z_STRLEN(params[1]));
	*str_len = Z_STRLEN(params[1]);
	zval_dtor(&retval);
	zval_dtor(&params[1]);
	return  SUCCESS;
}


/* {{{ void rsautil::encrypt($encrypted)
 */

PHP_METHOD(rsautil, encrypt)
{
	zend_long padding = 1;
	zend_string *data;

	zend_fcall_info fci;
	zend_fcall_info_cache fci_cache;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();

	zval *public_key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 , NULL);
	
	if (!public_key || Z_TYPE_P(public_key) != IS_RESOURCE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to public_key ");
		RETURN_FALSE;
	}

	zend_long split_length = 117;
	zend_string *str = NULL;
	int res;
	char *char_str = emalloc(split_length);
	int char_str_len;

	if (ZSTR_LEN(data) <= split_length) {
		res = call_funcion_with_param4(ZSTR_VAL(data), ZSTR_LEN(data), "openssl_public_encrypt", padding, public_key, &char_str, &char_str_len);
			if (res == SUCCESS) {
				str = php_base64_encode((unsigned char *)char_str, char_str_len);
				if (char_str) {
					efree(char_str);
				}
				RETURN_STR(str);
			} else {
				RETURN_EMPTY_STRING();
			}
	} else if (ZSTR_LEN(data) > split_length) {
		char *p;
		char *t = emalloc(split_length);
		size_t numelems;
		numelems = ZSTR_LEN(data) / split_length;
		smart_str            string = {0};
		p = ZSTR_VAL(data);
		while (numelems-- > 0) {
			memcpy(t, p, split_length);	
			 res = call_funcion_with_param4(t, split_length, "openssl_public_encrypt", padding, public_key, &char_str, &char_str_len);
			 if (res == SUCCESS) {
				smart_str_appendl(&string, char_str, char_str_len);
			 }
			 p += split_length;
		}	

		if (p != (ZSTR_VAL(data) + ZSTR_LEN(data))) {
			res = call_funcion_with_param4(p, (ZSTR_VAL(data) + ZSTR_LEN(data))-p, "openssl_public_encrypt", padding, public_key, &char_str, &char_str_len);
			if (res == SUCCESS) {
				smart_str_appendl(&string, char_str, char_str_len);
			}	
		}		
		smart_str_0(&string);
		if (t) {
			efree(t);
		}
		if (char_str) {
			efree(char_str);
		}
		if (string.s) {
			str = php_base64_encode((unsigned char *)ZSTR_VAL(string.s), ZSTR_LEN(string.s));
			smart_str_free(&string);
			RETURN_STR(str);
		} else {
			smart_str_free(&string);
			RETURN_EMPTY_STRING();
		}
		
	} else {
		RETURN_EMPTY_STRING();
	}

}
/* }}} */


PHP_METHOD(rsautil, decrypt)
{
	zend_long padding = 1;
	char *data;
	size_t data_len;
	zend_string *base64_str = NULL, *str = NULL;
	zend_long split_length = 128;
	zval *tmp, *private_key;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STRING(data, data_len)
	ZEND_PARSE_PARAMETERS_END();
		
	private_key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 , NULL);

	if (!private_key || Z_TYPE_P(private_key) != IS_RESOURCE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to private_key ");
		RETURN_EMPTY_STRING();
	}
	// base64_str = zend_string_init(data, data_len, 0);
	base64_str = php_base64_decode((unsigned char *)data, data_len);
	if (base64_str == NULL)
	{
		php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
		RETURN_EMPTY_STRING();
	}
	int res;
	char *char_str = emalloc(split_length);
	int char_str_len;

	if (ZSTR_LEN(base64_str) == split_length) {
		res = call_funcion_with_param4(ZSTR_VAL(base64_str), ZSTR_LEN(base64_str), "openssl_private_decrypt", padding, private_key, &char_str, &char_str_len);
		zend_string_release(base64_str);
		if (res == SUCCESS) {
			RETURN_STRINGL(char_str, char_str_len);
		} else {
			// zend_string_release(str);
			RETURN_EMPTY_STRING();
		}
	} else if (ZSTR_LEN(base64_str) > split_length) {
		char *p;
		char *t = emalloc(split_length);
		size_t numelems;
		numelems = ZSTR_LEN(base64_str) / split_length;
		smart_str    string = {0};
		p = ZSTR_VAL(base64_str);
	
		while (numelems-- > 0) {
			memcpy(t, p, split_length);	
			res = call_funcion_with_param4(t, split_length, "openssl_private_decrypt", padding, private_key, &char_str, &char_str_len);
			if (res == SUCCESS) {
				smart_str_appendl(&string, char_str, char_str_len);
			}
			p += split_length;
		}			
		smart_str_0(&string);
		if (t) {
			efree(t);
		}
		if (char_str) {
			efree(char_str);
		}
		zend_string_release(base64_str);
		if (string.s) {
			RETURN_STR(string.s);
		} else {
			smart_str_free(&string);
			RETURN_EMPTY_STRING();
		}
	} else {
		RETURN_EMPTY_STRING();
	}
}


/* {{{ void rsautil::sign($data, $signature_alg)
 */
PHP_METHOD(rsautil, sign)
{
	char * data;
	size_t data_len;
	zend_long signature_alg = 2;
	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STRING(data, data_len)
		Z_PARAM_LONG(signature_alg)
	ZEND_PARSE_PARAMETERS_END();


	zval *private_key;
	private_key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 , NULL);
	if (!private_key || Z_TYPE_P(private_key) != IS_RESOURCE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to private_key ");
		RETURN_FALSE;
	}
	// openssl_sign($data, $signature, $key, $algorithm);
	zval params[4];
	uint32_t param_cnt = 4;
	ZVAL_STRING(&params[0], data);
	ZVAL_NEW_REF(&params[1], &EG(uninitialized_zval));
	ZVAL_RES(&params[2], Z_RES_P(private_key));
	ZVAL_LONG(&params[3], signature_alg);

	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_sign");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, param_cnt, params))
	{
		 RETURN_FALSE;
	}
	zval * result = Z_REFVAL_P(&params[1]);
	zval_dtor(&params[0]);
	zval_dtor(&params[1]);
	zval_dtor(&params[2]);
	zval_dtor(&function_name);
	zval_dtor(private_key);
	RETURN_NEW_STR(php_base64_encode((unsigned char *)Z_STRVAL_P(result), Z_STRLEN_P(result)));
}



/* {{{ rsautil::verify($msg, $sign, $method = ALGO_MD5)
 */
PHP_METHOD(rsautil, verify)
{
	char * data;
	size_t data_len;
	char * signature;
	size_t signature_len;
	zend_long signature_alg = 2;
	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_STRING(data, data_len)
		Z_PARAM_STRING(signature, signature_len)
		Z_PARAM_LONG(signature_alg)
	ZEND_PARSE_PARAMETERS_END();
	
	zend_string *base64_str = php_base64_decode((unsigned char *)signature, signature_len);
	if (!base64_str && ZSTR_LEN(base64_str) < 1)
	{
		php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
		RETURN_FALSE;
	}
	// php_printf("base64_str = %s len=%d\n", ZSTR_VAL(base64_str), ZSTR_LEN(base64_str));

	zval * public_key;
	public_key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 , NULL);
	if (!public_key)
	{
		php_error_docref(NULL, E_WARNING, "Failed to publicKey ");
		RETURN_FALSE;
	}
	zval params[4];
	uint32_t param_cnt = 4;
	ZVAL_STRING(&params[0], data);
	ZVAL_STR_COPY(&params[1], base64_str);
	ZVAL_RES(&params[2], Z_RES_P(public_key));
	ZVAL_LONG(&params[3], signature_alg);
	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_verify");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, param_cnt, params))
	{
		 RETURN_FALSE;
	}
	zval_dtor(&params[0]);
	zval_dtor(&params[1]);
	zval_dtor(&params[2]);
	zval_dtor(public_key);
	zval_dtor(&function_name);
	zend_string_release(base64_str);
	RETURN_LONG(Z_LVAL(retval));
}

/* }}} */

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
	PHP_ME(rsautil, getPublicKey,   arginfo_rsautil_void,       ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPublicKey,   arginfo_rsautil_set_public, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPrivateKey, arginfo_rsautil_void,        ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPrivateKey, arginfo_rsautil_set_private, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPkcs12,      arginfo_rsautil_set_pkcs12, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, encrypt,        arginfo_rsautil_encrypt,    ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, decrypt,        arginfo_rsautil_decrypt,    ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, split,          arginfo_rsautil_split,      ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, sign,           arginfo_rsautil_sign,       ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, verify,         arginfo_rsautil_verify,     ZEND_ACC_PUBLIC)
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
