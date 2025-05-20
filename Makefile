build/testing_shared_lib: main.c build/gwconnlogger.so
	gcc $^ -o $@
build/gwconnlogger.so: connlogger.c
	gcc -shared -Os -fpic -fPIC $^ -o $@
