#include <windows.h>
#include <stdio.h>

int main() {
    char name[] = "\\\\.\\pipe\\ctest";
    HANDLE h = CreateNamedPipeA(name, 3, 6, 10, 4096, 4096, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Pipe created: %p\n", h);

    // Signal ready
    printf("READY\n");
    fflush(stdout);

    // Keep running for 30 seconds
    for (int i = 0; i < 30; i++) {
        BOOL connected = ConnectNamedPipe(h, NULL);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            printf("Client connected!\n");
            DisconnectNamedPipe(h);
        }
        Sleep(1000);
    }

    CloseHandle(h);
    return 0;
}
