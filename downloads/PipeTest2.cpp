#include <windows.h>
#include <stdio.h>

int main() {
    char name[] = "\\\\.\\pipe\\ctest";
    printf("Name: %s\n", name);
    printf("Bytes:");
    for (int i = 0; name[i]; i++) printf(" %02X", (unsigned char)name[i]);
    printf("\n");

    HANDLE h = CreateNamedPipeA(name, 3, 6, 10, 4096, 4096, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed: %lu\n", GetLastError());
        return 1;
    }
    printf("SUCCESS: handle=%p\n", h);
    printf("Press Enter to exit...\n");
    getchar();
    CloseHandle(h);
    return 0;
}
