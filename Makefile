build/testing_shared_lib: main.c build/gwconnlogger.so
	gcc -g3 $^ -o $@
build/gwconnlogger.so: connlogger.c
	gcc -shared -Os -g3 -fpic -fPIC $^ -o $@
