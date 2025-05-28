build/gwconnlogger.so: connlogger.c
	gcc -Wall -Wextra -Wpedantic -shared -Os -g3 -fpic -fPIC $^ -o $@
build/test.so: connlogger.c
	gcc -shared -O0 -g3 -fpic -fPIC $^ -o $@