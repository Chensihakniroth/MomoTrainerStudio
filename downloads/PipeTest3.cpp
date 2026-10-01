#include <windows.h>
#include <stdio.h>

int main() {
    // Test with the same name as Python
    char name[] = "\\\\.\\pipe\\simple_test_pipe";
    printf("Name: %s\n", name);

    HANDLE h = CreateNamedPipeA(name, 3, 6, 10, 4096, 4096, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed: %lu\n", GetLastError());
        return 1;
    }
    printf("SUCCESS: handle=%p\n", h);

    // Try to open it from the same process
    HANDLE h2 = CreateFileA(name, 0xC0000000, 0, NULL, 3, 0, NULL);
    if (h2 == INVALID_HANDLE_VALUE) {
        printf("Open failed: %lu\n", GetLastError());
    } else {
        printf("Open SUCCESS!\n");
        CloseHandle(h2);
    }

    CloseHandle(h);
    return 0;
}
