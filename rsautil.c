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


static zval *rsautil_encrypt(zend_string *data, zend_long padding, zval *public_key)
{
	zval params[4];
	uint32_t param_cnt = 4;
	ZVAL_STR_COPY(&params[0], data);
	ZVAL_NEW_EMPTY_REF(&params[1]);
	ZVAL_RES(&params[2], Z_RES_P(public_key));
	ZVAL_LONG(&params[3], padding);

	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_public_encrypt");
	int result = call_user_function(EG(function_table), NULL, &function_name, &retval, param_cnt, params);
	zval_dtor(&params[0]);
	zval_dtor(&params[2]);
	zval_dtor(&params[3]);
	zval_dtor(&function_name);
	if (result != SUCCESS || Z_TYPE(retval) != IS_TRUE) 
	{
		zval_dtor(&params[1]);
		zval_dtor(&retval);	
		php_error_docref(NULL, E_WARNING, "Failed to rsautil_decrypt ");
		return NULL;
	}	
	zval *retval2 = Z_REFVAL_P(&params[1]);
	zval_dtor(&retval);
	zval_dtor(&params[1]);
	return retval2;
}

static zval *rsautil_decrypt(const char *data, size_t data_len, zend_long padding, zval *key)
{

	zval params[4];
	uint32_t param_cnt = 4;

	ZVAL_STRINGL(&params[0], data, data_len);
	
	ZVAL_NEW_REF(&params[1], &EG(uninitialized_zval));
	ZVAL_RES(&params[2], Z_RES_P(key));
	ZVAL_LONG(&params[3], padding);

	zval function_name, retval;
	ZVAL_STRING(&function_name, "openssl_private_decrypt");

	
	int result =  call_user_function_ex(EG(function_table), NULL, &function_name, &retval, param_cnt, params, 0, NULL);

	zval_dtor(&params[0]);
	zval_dtor(&params[2]);
	zval_dtor(&params[3]);
	zval_dtor(&function_name);

	if (result != SUCCESS || Z_TYPE(retval) != IS_TRUE) 
	{
		zval_dtor(&params[1]);
		zval_dtor(&retval);	
		php_error_docref(NULL, E_WARNING, "Failed to rsautil_decrypt.");
		return NULL;
	}	
	zval *retval2 = Z_REFVAL_P(&params[1]);
	zval_dtor(&params[1]);
	zval_dtor(&retval);
	return retval2;
}

static zval *rsautil_str_split2(zend_string *str, zend_long split_length) {
	zval *dest;
	
	const char *p;
	size_t n_reg_segments;

	if (split_length <= 0) {
		php_error_docref(NULL, E_WARNING, "The length of each segment must be greater than zero");
		return NULL;
	}
	
	if (0 == ZSTR_LEN(str) || (size_t)split_length >= ZSTR_LEN(str)) {
		array_init_size(dest, 1);
		add_next_index_stringl(dest, ZSTR_VAL(str), ZSTR_LEN(str));	
	}

	array_init_size(dest, (uint32_t)(((ZSTR_LEN(str) - 1) / split_length) + 1));

	n_reg_segments = ZSTR_LEN(str) / split_length;
	p = ZSTR_VAL(str);

	while (n_reg_segments-- > 0) {
		add_next_index_stringl(dest, p, split_length);
		p += split_length;
	}

	if (p != (ZSTR_VAL(str) + ZSTR_LEN(str))) {
		add_next_index_stringl(dest, p, (ZSTR_VAL(str) + ZSTR_LEN(str) - p));
	}
	return dest;
}

static zval rsautil_str_split(zend_string *str, zend_long split_length)
{
	zval params[2];
	uint32_t param_cnt = 2;
	zval function_name, retval;

	ZVAL_STR_COPY(&params[0], str);
	ZVAL_LONG(&params[1], split_length)
	ZVAL_STRING(&function_name, "str_split");

	int result = call_user_function(EG(function_table), NULL, &function_name, &retval, param_cnt, params TSRMLS_CC);
	zval_dtor(&function_name);
	zval_dtor(&params[0]);
	
	if (SUCCESS != result || Z_TYPE(retval) == IS_FALSE)
	{
		php_error_docref(NULL, E_WARNING, "Failed to split. ");
	}
	return retval;
}

PHP_METHOD(rsautil, split)
{
	
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

	// php_printf("data=%s, password=%s\n", data, password);
	
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
	// php_debug_zval_dump(&params[1], 1);
	zval_ptr_dtor(pkcs12);
	ZVAL_UNREF(&params[1]);
	// zval_ptr_dtor(&params[1]);
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
		RETURN_FALSE;
	}

	base64_str = php_base64_decode((unsigned char *)data, data_len);
	if (!base64_str)
	{
		php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
		RETURN_FALSE;
	}
	
	if (ZSTR_LEN(base64_str) <= split_length) {
		// tmp = rsautil_decrypt(base64_str, padding, private_key);
		// zend_string_release(base64_str);
		// str = Z_STR_P(tmp);
		// zval_dtor(tmp);
		// RETURN_STR(str);
	} else {
	
	
	const char *p;
	size_t numelems;


	numelems = ZSTR_LEN(base64_str) / split_length;
	// php_printf("n_reg_segments=%d\n", n_reg_segments);
	p = ZSTR_VAL(base64_str);

	while (numelems-- > 0) {
		// add_next_index_stringl(dest, p, split_length);
		// php_printf("%s \n",  p);
		// php_printf(" size =  %d, split_length =%d\n",  strlen(p), split_length);
		p += split_length;
		tmp = rsautil_decrypt(p, split_length, padding, private_key);
		php_debug_zval_dump(tmp, 1);
		
		
		// tmp = rsautil_decrypt(zend_string_init(p, split_length, 0), padding, private_key);
	
			return ;
	}


	if (p != (ZSTR_VAL(base64_str) + ZSTR_LEN(base64_str))) {
		// add_next_index_stringl(dest, p, (ZSTR_VAL(base64_str) + ZSTR_LEN(base64_str) - p));
	}
	
	zend_string_release(base64_str);

	// HashTable *ht = Z_ARRVAL_P(arr);
	// uint32_t numelems = zend_hash_num_elements(ht);
	// size_t len = 117;
	// str = zend_string_safe_alloc(numelems - 1, len,  len * numelems, 0);
	// ZSTR_LEN(str) = 0;
	// zval *val;
	// ZEND_HASH_FOREACH_VAL(ht, val) {
	// 	ZVAL_DEREF(val);
	// 	ZVAL_DEREF(tmp);
	// 	tmp = rsautil_decrypt(Z_STR_P(val), padding, private_key);
	// 	if (tmp && Z_STRLEN_P(tmp) > 0) {
	// 		memcpy(ZSTR_VAL(str) + ZSTR_LEN(str), Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
	// 		ZSTR_LEN(str) += Z_STRLEN_P(tmp);
	// 	}
	// } ZEND_HASH_FOREACH_END();

	//  ZSTR_VAL(str)[ZSTR_LEN(str)] = '\0';
	//  RETURN_STR(str);
	}
}
// PHP_METHOD(rsautil, decrypt)
// {
// 	zend_long padding = 1;
// 	char *data;
// 	size_t data_len;
// 	zend_string *base64_str = NULL, *str = NULL;
// 	zend_long split_length = 128;
// 	zval *tmp, *private_key;

// 	ZEND_PARSE_PARAMETERS_START(1, 1)
// 	Z_PARAM_STRING(data, data_len)
// 	ZEND_PARSE_PARAMETERS_END();
		
// 	private_key = zend_read_property(rsautil_ce_ptr, getThis(), ZEND_STRL(PROPERTY_PRIVATEKEY), 1 , NULL);
// 	if (!private_key || Z_TYPE_P(private_key) != IS_RESOURCE)
// 	{
// 		php_error_docref(NULL, E_WARNING, "Failed to private_key ");
// 		RETURN_FALSE;
// 	}

// 	base64_str = php_base64_decode((unsigned char *)data, data_len);
// 	if (!base64_str)
// 	{
// 		php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
// 		RETURN_FALSE;
// 	}
	
// 	if (ZSTR_LEN(base64_str) <= split_length) {
// 		tmp = rsautil_decrypt(base64_str, padding, private_key);
// 		zend_string_release(base64_str);
// 		str = Z_STR_P(tmp);
// 		zval_dtor(tmp);
// 		RETURN_STR(str);
// 	} else {
	
// 	zval *arr = rsautil_str_split2(base64_str, split_length);
// 	if (arr == NULL){
// 	// if (Z_TYPE(arr) == IS_FALSE) {
// 		php_error_docref(NULL, E_WARNING, "Failed to rsautil_str_split ");
// 		RETURN_FALSE;
// 	}
// 	zend_string_release(base64_str);

// 	HashTable *ht = Z_ARRVAL_P(arr);
// 	uint32_t numelems = zend_hash_num_elements(ht);
// 	size_t len = 117;
// 	str = zend_string_safe_alloc(numelems - 1, len,  len * numelems, 0);
// 	ZSTR_LEN(str) = 0;
// 	zval *val;
// 	ZEND_HASH_FOREACH_VAL(ht, val) {
// 		ZVAL_DEREF(val);
// 		ZVAL_DEREF(tmp);
// 		tmp = rsautil_decrypt(Z_STR_P(val), padding, private_key);
// 		if (tmp && Z_STRLEN_P(tmp) > 0) {
// 			memcpy(ZSTR_VAL(str) + ZSTR_LEN(str), Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
// 			ZSTR_LEN(str) += Z_STRLEN_P(tmp);
// 		}
// 	} ZEND_HASH_FOREACH_END();

// 	 ZSTR_VAL(str)[ZSTR_LEN(str)] = '\0';
// 	 RETURN_STR(str);
// 	}
// }

/* {{{ void rsautil::encrypt($encrypted)
 */

PHP_METHOD(rsautil, encrypt)
{
	zend_long padding = 1;
	zend_string *data;

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
	
	zval arr = rsautil_str_split(data, split_length);
	if (Z_TYPE(arr) == IS_FALSE) {
		php_error_docref(NULL, E_WARNING, "Failed to rsautil_str_split ");
		RETURN_FALSE;
	}
	
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
			tmp = rsautil_encrypt(Z_STR_P(val), padding, public_key);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				zval_dtor(val);
				zval_dtor(tmp);
				str = php_base64_encode((unsigned char *)Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				RETURN_STR(str);
			} else {
				RETURN_EMPTY_STRING();
			}
			
		} ZEND_HASH_FOREACH_END();
	}

		size_t len = 128;
		str = zend_string_safe_alloc(numelems - 1, len, len * numelems, 0);
		ZSTR_LEN(str) = 0;
		
		ZEND_HASH_FOREACH_VAL(ht, val) {
			// ZVAL_DEREF(val);
			// ZVAL_DEREF(tmp);

			tmp = rsautil_encrypt(Z_STR_P(val), padding, public_key);
			if (tmp && Z_STRLEN_P(tmp) > 0) {
				memcpy(ZSTR_VAL(str) + ZSTR_LEN(str), Z_STRVAL_P(tmp), Z_STRLEN_P(tmp));
				ZSTR_LEN(str) += len;
			}
		} ZEND_HASH_FOREACH_END();

	 ZSTR_VAL(str)[ZSTR_LEN(str)] = '\0';
	
	RETURN_STR(php_base64_encode((unsigned char *)ZSTR_VAL(str), ZSTR_LEN(str)));
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
