void external_func(void) {
    int a = 10, b;
    asm("movl %1, %%eax;"
        "movl %%eax, %0;"
        :"=r" (b)
        :"r" (a)
        :"%eax"
        );
}
