/* Lesson 3.04: Normal Array Access */
#include <stdio.h>

void foo(void) {
    int arr[4] = {1, 2, 3, 4};
    printf("arr[0] = %d\n", arr[0]);
    printf("arr[1] = %d\n", arr[1]);
    printf("arr[2] = %d\n", arr[2]);
    printf("arr[3] = %d\n", arr[3]);
}

int main(void) {
    foo();
    return 0;
}
