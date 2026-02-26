/* Lesson 3.06: Buffer Overflow - Overwrite Variable */
#include <stdio.h>
#include <string.h>

void foo(void) {
    int secret = 0xdeadbeef;
    char buf[8];
    
    printf("Before overflow: secret = 0x%x\n", secret);
    
    /* Dangerous: gets() reads unbounded input and can overflow buf */
    printf("Enter something: ");
    gets(buf);  /* VULNERABLE */
    
    printf("After overflow: secret = 0x%x\n", secret);
}

int main(void) {
    foo();
    return 0;
}
