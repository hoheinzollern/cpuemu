int foo(int index, int val) {
    int arr[4] = {1, 2, 3, 4};
    int untouched = 0x1337;
    arr[index] = val;
    return untouched;
}

void main() {
    foo(7, 0xdead);  // Out of bounds!
}
