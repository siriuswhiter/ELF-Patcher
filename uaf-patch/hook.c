//gcc -Os -nostdlib -nodefaultlibs -fPIC -Wl,-shared hook.c -o hook
#include<stdlib.h>

void _free_(void **ptr){
	asm(
		"push %rbp\n"
		"mov %rsp, %rbp\n"
		"movq %rdi,%rbx\n"
		"movq (%rdi),%rdi\n"
		"call n\n"
		"movq $0,(%rbx)\n"
		"pop %rbp\n"
		"ret\n"
	        "n: nop\n"	
	);
}


