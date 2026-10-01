// Simple test: create pipe with global handle
#include <windows.h>
#include <stdio.h>

HANDLE g_hPipe = NULL;

void WriteLog(const char* msg) {
    FILE* f = fopen("C:\\Temp\\simple_debug.txt", "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

BOOL APIENTRY DllMain(HMODULE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DWORD pid = GetCurrentProcessId();
        
        char pipeName[256];
        sprintf(pipeName, "\\\\.\\pipe\\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_%lu", pid);
        
        g_hPipe = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, NULL
        );
        
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            char log[256];
            sprintf(log, "PID=%lu pipe=%s FAILED: %lu", pid, pipeName, GetLastError());
            WriteLog(log);
            g_hPipe = NULL;
        } else {
            char log[256];
            sprintf(log, "PID=%lu pipe=%s SUCCESS handle=%p", pid, pipeName, g_hPipe);
            WriteLog(log);
        }
    }
    return TRUE;
}
