/* Lesson 3.07: Buffer Overflow - Overwrite Return Address */
#include <stdio.h>
#include <string.h>

void evil(void) {
    printf("PWNED! You jumped into evil()!\n");
}

void vulnerable(void) {
    char buf[8];
    
    printf("Enter something: ");
    gets(buf);  /* VULNERABLE - can overflow and overwrite return address */
}

int main(void) {
    printf("evil() function is at 0x%lx\n", (unsigned long)&evil);
    vulnerable();
    printf("Returned from vulnerable()\n");
    return 0;
}
