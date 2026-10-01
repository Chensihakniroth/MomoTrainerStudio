// Standalone pipe test - compile as exe
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD pid = GetCurrentProcessId();
    char pipeName[256];
    sprintf(pipeName, "\\\\.\\pipe\\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_%lu", pid);
    
    printf("Creating pipe: %s\n", pipeName);
    
    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096, 4096, 0, NULL
    );
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipeA failed: %lu\n", GetLastError());
        return 1;
    }
    
    printf("Pipe created: handle=%p\n", hPipe);
    printf("Waiting for connections... (press Ctrl+C to exit)\n");
    
    while (1) {
        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            printf("Client connected!\n");
            // Echo loop
            char buf[4096];
            DWORD read;
            while (ReadFile(hPipe, buf, sizeof(buf)-1, &read, NULL)) {
                buf[read] = 0;
                printf("Received: %s\n", buf);
                WriteFile(hPipe, buf, read, &read, NULL);
            }
            printf("Client disconnected\n");
            DisconnectNamedPipe(hPipe);
        }
        Sleep(100);
    }
    
    CloseHandle(hPipe);
    return 0;
}
