// Minimal CRT-free DLL - pure Win32 API only
#include <windows.h>
#include <cstdio>
#include <cstring>

// Thread-safe console output via pipe
static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static bool g_running = true;

void PipeSend(const char* msg) {
    if (!g_pipe || g_pipe == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(g_pipe, msg, (DWORD)strlen(msg), &written, NULL);
}

void ProcessPipe() {
    char buffer[4096];
    DWORD bytesRead = 0;

    while (g_running && g_pipe && g_pipe != INVALID_HANDLE_VALUE) {
        if (ReadFile(g_pipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';

            char response[8192];
            DWORD written = 0;

            if (strstr(buffer, "print(")) {
                char* start = strchr(buffer, '\"');
                if (start) {
                    start++;
                    char* end = strchr(start, '\"');
                    if (end) {
                        *end = '\0';
                        snprintf(response, sizeof(response), "\n%s\n", start);
                    }
                } else {
                    snprintf(response, sizeof(buffer), "\n%s\n", buffer);
                }
            } else {
                snprintf(response, sizeof(buffer), "\n%s\n", buffer);
            }

            WriteFile(g_pipe, response, (DWORD)strlen(response), &written, NULL);
        }
    }
}

DWORD WINAPI PipeThread(LPVOID param) {
    WCHAR pipeName[256];
    swprintf(pipeName, 256, L"\\\\.\\pipe\\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_%d", GetCurrentProcessId());

    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096, 4096, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return 1;
    }

    g_pipe = hPipe;
    ConnectNamedPipe(hPipe, NULL);
    ProcessPipe();

    CloseHandle(hPipe);
    g_pipe = INVALID_HANDLE_VALUE;
    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        g_running = false;
        if (g_pipe && g_pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_pipe);
        }
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL IsRunning() { return g_running; }
extern "C" __declspec(dllexport) void StopPipe() { g_running = false; }
