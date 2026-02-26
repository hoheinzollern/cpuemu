/* Lesson 3.05: Array Out-of-Bounds Access */
#include <stdio.h>

void foo(void) {
    int arr[4] = {1, 2, 3, 4};
    printf("arr[0] = %d\n", arr[0]);
    printf("arr[4] = %d\n", arr[4]);    /* Out of bounds read */
    printf("arr[5] = %d\n", arr[5]);    /* Out of bounds read */
}

int main(void) {
    foo();
    return 0;
}
