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

zend_class_entry *rsautil_ce;
/* {{{ void rsautil_test1()
 */
PHP_FUNCTION(rsautil_test1)
{
	
}
/* }}} */

/* {{{ string rsautil_test2( [ string $var ] )
 */
PHP_FUNCTION(rsautil_test2)
{
	char *var = "World";
	size_t var_len = sizeof("World") - 1;
	zend_string *retval;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_STRING(var, var_len)
	ZEND_PARSE_PARAMETERS_END();

	retval = strpprintf(0, "Hello %s", var);

	RETURN_STR(retval);
}
/* }}}*/

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

PHP_METHOD(rsautil, getPublicKey) {
	
	zend_class_entry *ce;
	zval  rv, *key;
	key = zend_read_property(ce, getThis(), "publickey", sizeof("publickey")-1, 1 TSRMLS_DC, &rv);
	zval_dtor(&rv);
	RETURN_ZVAL(key, 0, 0);
}

PHP_METHOD(rsautil, getPrivateKey) {
	
	zend_class_entry *ce;
	zval  rv, *key;
	key = zend_read_property(ce, getThis(), "privatekey", sizeof("privatekey")-1, 1 TSRMLS_DC, &rv);
	zval_dtor(&rv);
	RETURN_ZVAL(key, 0, 0);
}

//openssl_pkcs12_read($cer, self::$certInfo, $password)
static zval getPkcs12(zend_string *data, zend_string *password) {
	const uint32_t MAX_PARAMS = 3;
	zval function_name, retval, callback_params[MAX_PARAMS];
	zval *crypted;
	uint32_t call_func_param_cnt = MAX_PARAMS;
	
	ZVAL_STRING(&function_name, "openssl_pkcs12_read");
	ZVAL_STR_COPY(&callback_params[0], data);
	ZVAL_NEW_EMPTY_REF(&callback_params[1]);
	ZVAL_STR_COPY(&callback_params[2], password);
	
    if(SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval, call_func_param_cnt, callback_params TSRMLS_CC)){
        // ZVAL_FALSE(&retval);
    }
	// php_var_dump(data, 1);   
//	 php_debug_zval_dump(&callback_params[1], 2);
	// php_debug_zval_dump(&retval, 1);
	
//	php_var_dump(convert_to_array(&callback_params[1]), 2);
	return callback_params[1];
}

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
/**
$Rsa->setPrivateKey(data, password, crypted)
**/
PHP_METHOD(rsautil, setPrivateKey) {
	zend_class_entry *ce;
	zend_string *data, *password, *keyData;
	zval   result;
	
	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(data)
		Z_PARAM_STR(password)
	ZEND_PARSE_PARAMETERS_END();

	zval function_name, retval, callback_params2[2];

	result = getPkcs12(data, password);

	const char *keyStr = "pkey";
	size_t keyStrLen = strlen(keyStr);
	HashTable        *myht;
	myht = Z_ARRVAL(result);
	zval *arr;
	
	zval  *entry, prefix;
//	ZVAL_STRING(&string_key, "pkey");
	zval _key, _val;
zend_string *string_key;
	string_key = zned_string_init("pkey", sizeof("pkey")-1, 0);

	zend_ulong num_key;

	 array_init_size(return_value, zend_hash_num_elements(Z_ARRVAL_P(arr)));
	
	ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(arr), ) {
			if (string_key && zend_hash_exists(Z_ARRVAL_P(prefix), string_key)) {
//				prefix_entry = zend_hash_find(Z_ARRVAL_P(prefix), string_key);
//				if (Z_TYPE_P(entry) == IS_STRING && prefix_entry != NULL && Z_TYPE_P(prefix_entry) == IS_STRING) {
//					result = strpprintf(0, "%s%s", Z_STRVAL_P(prefix_entry), Z_STRVAL_P(entry));
//					ZVAL_STR(&value, result);
//					zend_hash_update(Z_ARRVAL_P(return_value), string_key, &value);
//				}   
			} 
		}ZEND_HASH_FOREACH_END();
//	RETURN_STR(Z_TYPE_P(&result));
//	ZVAL_STRINGL(&zcert, "12321313", sizeof("12321313")-1);
//	add_next_index_str(zout, zend_string_copy("cert"));
//	php_debug_zval_dump(&result, 1000);
//php_printf(convert_to_array(&result));
//	RETURN_LONG(zend_hash_num_elements(Z_ARRVAL_P(&result)));
//	RETURN_ARR(Z_ARRVAL_P(&result));
//	RETURN_ZVAL(&result, 0, 0);
//	zval *res2;
	// string_key = zned_string_init("pkey", sizeof("pkey")-1, 0);
	// zval *tmp = Z_ARRVAL_P(&result);
	// res2 = zend_hash_str_find(myht, "pkey", sizeof("pkey")-1);
	// php_debug_zval_dump(Z_ARR(result), 2);
	// tmpzval = zend_hash_str_find(Z_ARR(result), "pkey", sizeof("pkey")-1);
	// zend_hash_str_del(Z_ARRVAL_P(&result), "pkey", sizeof("pkey")-1);

	// if (NULL != (tmp = zend_hash_str_find(Z_ARRVAL_P(&result), "pkey", sizeof("pkey")-1) )){
	// // 		// convert_to_string_ex(tmp);
	// // 		// server_name = Z_STRVAL_P(tmp);
	// // 		// server_name_len = Z_STRLEN_P(tmp);
	// // 		// ctx = CLSCTX_REMOTE_SERVER;
	// 	}
// php_var_dump(result, 2);
	// php_debug_zval_dump(&result, 2);
	// php_debug_zval_dump(&crypted, 2);
	// keyData = Z_STR(getPkcs12(data, password));

	// RETURN_ZVAL(crypted, 0, 0);
	// getKey(keyData);
	// zend_update_property(ce, getThis(), "privateKey", sizeof("privateKey")-1, &retval TSRMLS_CC);
    // zval_dtor(&retval);
//	RETURN_TRUE;
}


PHP_METHOD(rsautil, setPublicKey) {
	zend_class_entry *ce;
	zend_string *data;
	zval retval;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();
	retval = getKey(data);
	zend_update_property(ce, getThis(), "publickey", sizeof("publickey")-1, &retval TSRMLS_CC);
    zval_dtor(&retval);
	RETURN_TRUE;
}

/* {{{ void rsautil::encrypt()
 */
PHP_METHOD(rsautil, encrypt)
{
	zval *key, *crypted;
	zend_resource *keyresource = NULL;
	zend_long padding = 1;
	char * data;
	size_t data_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz/z|l", &data, &data_len, &crypted, &key, &padding) == FAILURE)
		return;
	RETVAL_FALSE;

	zval  *value,  rv, callback_params[4];

	ZVAL_STRING(&callback_params[0], data);

	ZVAL_NEW_REF(&callback_params[1], crypted);
	Z_ADDREF(callback_params[1]);
	ZVAL_RES(&callback_params[2], Z_RES_P(key));
	// Z_ADDREF(callback_params[2]);
	ZVAL_LONG(&callback_params[3], 1)
	
	zval function_name, retval;
	uint32_t call_func_param_cnt = 4;
	ZVAL_STRING(&function_name, "openssl_public_encrypt");

    if(SUCCESS != call_user_function(EG(function_table), NULL, &function_name, &retval , call_func_param_cnt, callback_params)){
        RETURN_FALSE;
    }   

	
	RETURN_STR(php_base64_encode((unsigned char*)Z_STRVAL_P(&callback_params[1]), Z_STRLEN_P(&callback_params[1])));
	return;

}
/* }}} */

/* {{{ arginfo
 */
ZEND_BEGIN_ARG_INFO(arginfo_rsautil_test1, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rsautil_test2, 0)
	ZEND_ARG_INFO(0, str)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_encrypt, 0, 0, 1)
	ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rsautil_set_public, 0)
	ZEND_ARG_INFO(0, cert)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_rsautil_set_private, 0, 0, 1)
	ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, password)
	ZEND_ARG_INFO(1, crypted)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_rsautil_void, 0)
ZEND_END_ARG_INFO()
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
	PHP_FE(rsautil_test1,		arginfo_rsautil_test1)
	PHP_FE(rsautil_test2,		arginfo_rsautil_test2)
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
	
	PHP_FE_END
};
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

// 模块初始化时调用
PHP_MINIT_FUNCTION(rsautil) /* {{{ */ {
    zend_class_entry ce;
	//REGISTER_INI_ENTRIES(); // 注册ini
	INIT_CLASS_ENTRY(ce, "RSAUtil", rsautil_methods); //注册类及类方法
    rsautil_ce = zend_register_internal_class(&ce TSRMLS_CC);
	//添加属性
	zend_declare_property_null(rsautil_ce, "publicKey", strlen("publicKey"), ZEND_ACC_STATIC|ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(rsautil_ce, "privateKey", strlen("privateKey"), ZEND_ACC_STATIC|ZEND_ACC_PUBLIC TSRMLS_CC);

    return SUCCESS;
}
/* }}} */

#ifdef COMPILE_DL_RSAUTIL
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(rsautil)
#endif

