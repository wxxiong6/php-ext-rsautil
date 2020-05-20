
export USE_ZEND_ALLOC=0

export ZEND_DONT_UNLOAD_MODULES=1

valgrind --tool=memcheck --leak-check=full  --show-leak-kinds=all --num-callers=30 --log-file=php.log  php72 test.php
# valgrind --tool=memcheck --leak-check=full  --show-leak-kinds=all --num-callers=30 --log-file=php.log  php72 test_connection.php


