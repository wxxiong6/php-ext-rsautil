#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_var.h"
#include "ext/standard/base64.h"
#include "php_rsautil.h"
#include <string.h>

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_setPkcs12, 0, 0, 1)
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


static zval *rsautil_encrypt(zend_string *data, zend_long padding, zval *pulbicKey)
{
	zval callback_params[4];
	uint32_t call_func_param_cnt = 4;
	ZVAL_STR_COPY(&callback_params[0], data);
	ZVAL_NEW_EMPTY_REF(&callback_params[1]);
	ZVAL_RES(&callback_params[2], Z_RES_P(pulbicKey));
	ZVAL_LONG(&callback_params[3], padding);

	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_public_encrypt");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params))
	{
		return NULL;
	}
	zval_dtor(pulbicKey);
	zval_dtor(&retval);
	return Z_REFVAL_P(&callback_params[1]);
}

static zval *rsautil_decrypt(zend_string *data, zend_long padding, zval *privateKey)
{
	zval callback_params[4];
	uint32_t call_func_param_cnt = 4;
	ZVAL_STR_COPY(&callback_params[0], data);
	ZVAL_NEW_EMPTY_REF(&callback_params[1]);
	ZVAL_RES(&callback_params[2], Z_RES_P(privateKey));
	ZVAL_LONG(&callback_params[3], padding)

	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_private_decrypt");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params))
	{
		return NULL;
	}
	zval_dtor(privateKey);
	zval_dtor(&retval);
	return Z_REFVAL_P(&callback_params[1]);
}

static zval rsautil_str_split(zend_string *str, zend_long split_length)
{
	zval callback_params[2];
	uint32_t call_func_param_cnt = 2;
	ZVAL_STR_COPY(&callback_params[0], str);
	ZVAL_LONG(&callback_params[1], split_length)

	zval function_name, retval;
	ZVAL_STRING(&function_name, "str_split");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params))
	{
		// return NULL;
	}
	return retval;
}

PHP_METHOD(rsautil, split)
{
	zend_string *data;
	zend_long split_length = 1;
	ZEND_PARSE_PARAMETERS_START(2, 2)
	Z_PARAM_STR(data)
	Z_PARAM_LONG(split_length)
	ZEND_PARSE_PARAMETERS_END();
	zval arr = rsautil_str_split(data, split_length);
	// php_var_dump(&arr, 1);

	HashTable *ht = Z_ARRVAL(arr);
	// php_printf("array_size=%d, element=%d \n ", zend_array_count(ht), zend_hash_num_elements(ht));

	zval *pulbicKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 , NULL);
	if (!pulbicKey)
	{
		php_error_docref(NULL, E_WARNING, "Failed to pulbicKey ");
		RETURN_FALSE;
	}
	
		zend_string *str = NULL;
        uint32_t numelems = zend_hash_num_elements(ht);
		uint32_t len = 128;
		str = zend_string_safe_alloc(numelems - 1, len, len * numelems, 0);
		ZSTR_LEN(str) = 0;
		zval *val;
		zval *tmp;
		ZEND_HASH_FOREACH_VAL(ht, val) {
			ZVAL_DEREF(val);
			
			tmp = rsautil_encrypt(Z_STR_P(val), 1, pulbicKey);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				memcpy(ZSTR_VAL(str) + ZSTR_LEN(str), Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				ZSTR_LEN(str) += len;
			}
			ZVAL_DEREF(tmp);
		} ZEND_HASH_FOREACH_END();

	 ZSTR_VAL(str)[ZSTR_LEN(str)] = '\0';
	RETURN_NEW_STR(str);
}


static void rsautil_get_property(char *name, size_t name_len, INTERNAL_FUNCTION_PARAMETERS)
{
	zval *res, rv;

	if (zend_parse_parameters_none() == FAILURE)
	{
		return;
	}
	res = zend_read_property(rsautil_ce_ptr, getThis(), name, name_len, 1, &rv);
	ZVAL_DEREF(res);
	ZVAL_COPY(return_value, res);
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
	zval function_name, retval, callback_params[1];
	uint32_t call_func_param_cnt = 1;
	ZVAL_STRING(&function_name, fun_name);

	ZVAL_STR_COPY(&callback_params[0], data);
	//call
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params TSRMLS_CC))
	{
		ZVAL_FALSE(&retval);
	}
	zval_ptr_dtor(&callback_params[0]);
	zval_ptr_dtor(&function_name);
	return retval;
}

PHP_METHOD(rsautil, setPkcs12)
{
	zend_string *data, *password;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(data)
		Z_PARAM_STR(password)
	ZEND_PARSE_PARAMETERS_END();


	zval function_name, retval, callback_params[3];

	uint32_t call_func_param_cnt = 3;

	ZVAL_STRING(&function_name, "openssl_pkcs12_read");
	ZVAL_STR_COPY(&callback_params[0], data);
	ZVAL_NEW_REF(&callback_params[1], &EG(uninitialized_zval));
	ZVAL_STR_COPY(&callback_params[2], password);

	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params TSRMLS_CC))
	{
		RETURN_FALSE;
	}
	zval_ptr_dtor(&function_name);
	zval_ptr_dtor(&callback_params[0]);
	zval_ptr_dtor(&callback_params[2]);
	zval *pkcs12;
	// zval *pkcs12 = ZVAL_COPY(Z_REFVAL_P(&callback_params[1]));
	// zval_ptr_dtor(&callback_params[1]);

	if (Z_ISREF(callback_params[3]) && Z_TYPE_P(Z_REFVAL(callback_params[3])) == IS_ARRAY) {
		ZVAL_ZVAL(pkcs12,  Z_REFVAL_P(&callback_params[1], 0, 1);
			// ZVAL_COPY(pkcs12, Z_REFVAL_P(&callback_params[1]));
	}

	zend_array *zarr;
	zarr = Z_ARR_P(pkcs12);

	zval *zv_pkey = zend_hash_str_find(zarr, ZEND_STRL("pkey"));
	if (zv_pkey && Z_TYPE_P(zv_pkey) && Z_STRLEN_P(zv_pkey) > 0)
	{
		zval retval2;
		retval2 = get_key_source(Z_STR_P(zv_pkey), "openssl_pkey_get_private");
		zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), &retval2 TSRMLS_CC);
		ZVAL_DEREF(zv_pkey);
		zval_dtor(&retval2);
	}

	zval *zv_cert = zend_hash_str_find(zarr, ZEND_STRL("zv_cert"));
	if (zv_cert && zv_pkey)
	{
		zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PKCS12), pkcs12 TSRMLS_CC);
		ZVAL_DEREF(pkcs12);
	}
	php_debug_zval_dump(&callback_params[1], 1);
	zval_ptr_dtor(pkcs12);
	// zval_ptr_dtor(&callback_params[1]);
	RETURN_TRUE;
}

/**
$rsa->setPrivateKey(data, password, crypted)
**/
PHP_METHOD(rsautil, setPrivateKey)
{
	zend_string *data;
	zval retval;
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();
	retval = get_key_source(data, "openssl_pkey_get_private");
	zend_update_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), &retval TSRMLS_CC);
	zval_dtor(&retval);
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
	zval_dtor(&retval);
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


PHP_METHOD(rsautil, decrypt)
{
	zend_long padding = 1;
	char *data;
	size_t data_len;
	zend_string *base64_str = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 1)
	Z_PARAM_STRING(data, data_len)
	ZEND_PARSE_PARAMETERS_END();

	zval *privateKey;
	privateKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 , NULL);
	if (!privateKey || Z_TYPE_P(privateKey) != IS_RESOURCE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to privateKey ");
		RETURN_FALSE;
	}

	base64_str = php_base64_decode((unsigned char *)data, data_len);
	if (!base64_str)
	{
		php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
		RETURN_FALSE;
	}


	zend_long split_length = 128;
	zval arr = rsautil_str_split(base64_str, split_length);
	HashTable *ht = Z_ARRVAL(arr);
	zend_string *str = NULL;
    uint32_t numelems = zend_hash_num_elements(ht);
	zval *val;
	zval *tmp;

	if (numelems == 0) {
		RETURN_EMPTY_STRING();
	} else if (numelems == 1) {
		/* loop to search the first not undefined element... */
		ZEND_HASH_FOREACH_VAL(ht, val) {
			tmp = rsautil_decrypt(Z_STR_P(val), 1, privateKey);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				RETURN_STR(zval_get_string(tmp));
			}
			
		} ZEND_HASH_FOREACH_END();
	}

		size_t len = 0;
		str = zend_string_safe_alloc(numelems - 1, 117, 117 * numelems, 0);
		ZSTR_LEN(str) = 0;
		
		ZEND_HASH_FOREACH_VAL(ht, val) {
			ZVAL_DEREF(val);
			ZVAL_DEREF(tmp);

			tmp = rsautil_decrypt(Z_STR_P(val), padding, privateKey);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				memcpy(ZSTR_VAL(str) + ZSTR_LEN(str), Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				ZSTR_LEN(str) += Z_STRLEN_P(tmp);
				len += Z_STRLEN_P(tmp);
			}
		} ZEND_HASH_FOREACH_END();

	 ZSTR_VAL(str)[len] = '\0';
	RETURN_NEW_STR(str);
}

/* {{{ void rsautil::encrypt($encrypted)
 */
PHP_METHOD(rsautil, encrypt)
{
	zend_long padding = 1;
	zend_string *data;

	ZEND_PARSE_PARAMETERS_START(1, 1)
	Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();

	zval *pulbicKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 , NULL);
	
	if (!pulbicKey || Z_TYPE_P(pulbicKey) != IS_RESOURCE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to pulbicKey ");
		RETURN_FALSE;
	}
	zend_long split_length = 117;
	zval arr = rsautil_str_split(data, split_length);
	HashTable *ht = Z_ARRVAL(arr);
	zend_string *str = NULL;
        uint32_t numelems = zend_hash_num_elements(ht);

	zval *val;
	zval *tmp;

	if (numelems == 0) {
		RETURN_EMPTY_STRING();
	} else if (numelems == 1) {
		/* loop to search the first not undefined element... */
		ZEND_HASH_FOREACH_VAL(ht, val) {
			tmp = rsautil_encrypt(Z_STR_P(val), padding, pulbicKey);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				RETURN_NEW_STR(php_base64_encode((unsigned char *)Z_STRVAL_P(tmp), Z_STRLEN_P(tmp)));
			}
			
		} ZEND_HASH_FOREACH_END();
	}

		size_t len = 128;
		str = zend_string_safe_alloc(numelems - 1, len, len * numelems, 0);
		ZSTR_LEN(str) = 0;
		
		ZEND_HASH_FOREACH_VAL(ht, val) {
			ZVAL_DEREF(val);
			ZVAL_DEREF(tmp);

			tmp = rsautil_encrypt(Z_STR_P(val), 1, pulbicKey);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				memcpy(ZSTR_VAL(str) + ZSTR_LEN(str), Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				ZSTR_LEN(str) += len;
			}
		} ZEND_HASH_FOREACH_END();

	 ZSTR_VAL(str)[ZSTR_LEN(str)] = '\0';
	
	RETURN_NEW_STR(php_base64_encode((unsigned char *)ZSTR_VAL(str), ZSTR_LEN(str)));
}
/* }}} */

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


	zval *privateKey;
	privateKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 , NULL);
	if (!privateKey || Z_TYPE_P(privateKey) != IS_RESOURCE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to privateKey ");
		RETURN_FALSE;
	}
	// openssl_sign($data, $signature, $key, $algorithm);
	zval callback_params[4];
	uint32_t call_func_param_cnt = 4;
	ZVAL_STRING(&callback_params[0], data);
	ZVAL_NEW_REF(&callback_params[1], &EG(uninitialized_zval));
	ZVAL_RES(&callback_params[2], Z_RES_P(privateKey));
	ZVAL_LONG(&callback_params[3], signature_alg);

	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_sign");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params))
	{
		 RETURN_FALSE;
	}
	zval * result = Z_REFVAL_P(&callback_params[1]);
	// php_var_dump(&retval, 1);
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

	zval *publicKey;
	publicKey = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PUBLICKEY), 1 , NULL);
	if (!publicKey)
	{
		php_error_docref(NULL, E_WARNING, "Failed to publicKey ");
		RETURN_FALSE;
	}
	zval callback_params[4];
	uint32_t call_func_param_cnt = 4;
	ZVAL_STRING(&callback_params[0], data);
	ZVAL_STR_COPY(&callback_params[1], base64_str);
	ZVAL_RES(&callback_params[2], Z_RES_P(publicKey));
	ZVAL_LONG(&callback_params[3], signature_alg);
	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_verify");
	if (SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params))
	{
		 RETURN_FALSE;
	}
	// php_var_dump(&retval, 1);
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
	PHP_ME(rsautil, encrypt, arginfo_rsautil_encrypt, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPublicKey, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPublicKey, arginfo_rsautil_set_public, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPrivateKey, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPrivateKey, arginfo_rsautil_set_private, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, setPkcs12, arginfo_rsautil_set_setPkcs12, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, getPkcs12, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, decrypt, arginfo_rsautil_decrypt, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, split, arginfo_rsautil_void, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, sign, arginfo_rsautil_sign, ZEND_ACC_PUBLIC)
	PHP_ME(rsautil, verify, arginfo_rsautil_verify, ZEND_ACC_PUBLIC)
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
