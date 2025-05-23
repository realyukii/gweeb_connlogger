build/gwconnlogger.so: connlogger.c
	gcc -shared -Os -g3 -fpic -fPIC $^ -o $@
build/test.so: file.c
	gcc -shared -Os -g3 -fpic -fPIC $^ -o $@