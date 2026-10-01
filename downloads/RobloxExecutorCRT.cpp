// Truly CRT-free DLL with file-based debug checkpoints.
#include <windows.h>

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static bool g_running = true;

// Manual string formatting - no CRT
void PipeSend(const char* msg) {
    if (!g_pipe || g_pipe == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(g_pipe, msg, (DWORD)strlen(msg), &written, NULL);
}

// Write debug checkpoint to file - no CRT, just WriteFile
void DebugCheckpoint(const char* msg) {
    DWORD written = 0;
    // Use a fixed path: C:\Temp\momo_debug.txt
    HANDLE hFile = CreateFileA(
        "C:\\Temp\\momo_debug.txt",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE) {
        // Append newline
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        const char* nl = "\r\n";
        WriteFile(hFile, nl, 2, &written, NULL);
        CloseHandle(hFile);
    }
}

// Build pipe name manually - no swprintf
void BuildPipeName(wchar_t* buf, DWORD pid) {
    const wchar_t prefix[] = L"\\\\.\\pipe\\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_";
    int i = 0;
    for (int j = 0; prefix[j]; j++) buf[i++] = prefix[j];
    char pidStr[16];
    int pidLen = 0;
    if (pid == 0) { pidStr[0] = '0'; pidLen = 1; }
    else {
        char temp[16];
        int k = 0;
        while (pid > 0) {
            temp[k++] = '0' + (char)(pid % 10);
            pid /= 10;
        }
        while (k > 0) { pidStr[pidLen++] = temp[--k]; }
    }
    pidStr[pidLen] = '\0';
    for (int j = 0; j < pidLen; j++) buf[i++] = (wchar_t)(unsigned char)pidStr[j];
    buf[i] = L'\0';
}

void ProcessPipe() {
    char buffer[4096];
    char response[8192];
    DWORD bytesRead = 0;
    while (g_running && g_pipe && g_pipe != INVALID_HANDLE_VALUE) {
        if (ReadFile(g_pipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            int outPos = 0;
            response[outPos++] = '\r';
            response[outPos++] = '\n';
            const char* p = buffer;
            while (*p && outPos < 8190) {
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"' && outPos < 8190) response[outPos++] = *p++;
                    if (*p == '"') p++;
                    break;
                }
                p++;
            }
            response[outPos++] = '\r';
            response[outPos++] = '\n';
            response[outPos] = '\0';
            PipeSend(response);
        }
    }
}

DWORD WINAPI PipeThread(LPVOID param) {
    DebugCheckpoint("PipeThread started");

    wchar_t pipeName[256];
    BuildPipeName(pipeName, GetCurrentProcessId());
    DebugCheckpoint("Pipe name built");

    // Convert to ASCII for debug
    char asciiName[512];
    int ai = 0;
    for (int i = 0; pipeName[i] && ai < 510; i++) {
        asciiName[ai++] = (char)pipeName[i];
    }
    asciiName[ai] = '\0';
    DebugCheckpoint(asciiName);

    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096, 4096, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char buf[64];
        buf[0] = 'C'; buf[1] = 'r'; buf[2] = 'e'; buf[3] = 'a'; buf[4] = 't'; buf[5] = 'e';
        buf[6] = 'N'; buf[7] = 'a'; buf[8] = 'm'; buf[9] = 'e'; buf[10] = 'd'; buf[11] = 'P';
        buf[12] = 'i'; buf[13] = 'p'; buf[14] = 'e'; buf[15] = ' '; buf[16] = 'f'; buf[17] = 'a';
        buf[18] = 'i'; buf[19] = 'l'; buf[20] = 'e'; buf[21] = 'd'; buf[22] = ' '; buf[23] = 'e'; buf[24] = 'r';
        buf[25] = 'r'; buf[26] = '=';
        // Convert error to string manually
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        char msg[64] = "CreateNamedPipeW failed: ";
        DWORD err = GetLastError();
        // Convert err to string
        char errStr[16];
        int ei = 0;
        if (err == 0) { errStr[ei++] = '0'; }
        else {
            char temp[16];
            int ti = 0;
            while (err > 0) { temp[ti++] = '0' + (char)(err % 10); err /= 10; }
            while (ti > 0) errStr[ei++] = temp[--ti];
        }
        errStr[ei] = '\0';
        // Append errStr to msg
        int mi = 29;
        for (int i = 0; errStr[i]; i++) msg[mi++] = errStr[i];
        DebugCheckpoint(msg);
        return 1;
    }

    g_pipe = hPipe;
    DebugCheckpoint("Pipe created OK");

    ConnectNamedPipe(hPipe, NULL);
    DebugCheckpoint("Connected to pipe");
    ProcessPipe();

    CloseHandle(hPipe);
    DebugCheckpoint("Pipe closed");
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
