all: build/gwconnlogger.so build/debug.so

build/gwconnlogger.so: connlogger.c
	gcc -Wall -Wextra -shared -Os -fpic -fPIC $^ -o $@
build/debug.so: connlogger.c
	gcc -shared -O0 -g3 -fpic -fPIC $^ -o $@