// CRT-free pipe DLL — NO C runtime at all
// Only uses kernel32.dll functions, no msvcrt, no CRT startup
// Compiled with: x86_64-w64-mingw32-g++ -shared -nostdlib -o PipeTestCRTFree.dll PipeTestCRTFree.cpp -lkernel32
//
// Stack probe: We avoid large stack allocations (>4KB) so __chkstk_ms is not needed.

#include <windows.h>

// ============================================================
// Helpers — CRT-free string/integer utils
// ============================================================

static DWORD myStrLen(const char* s) {
    DWORD len = 0;
    while (s[len]) len++;
    return len;
}

static void myCopyStr(char* dst, const char* src) {
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

static void myAppendStr(char* dst, const char* src) {
    while (*dst) dst++;
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

static void myAppendDword(char* dst, DWORD val) {
    while (*dst) dst++;
    if (val == 0) { *dst++ = '0'; *dst = '\0'; return; }
    char tmp[16];
    int i = 0;
    while (val > 0) { tmp[i++] = '0' + (char)(val % 10); val /= 10; }
    for (int j = i - 1; j >= 0; j--) *dst++ = tmp[j];
    *dst = '\0';
}

// ============================================================
// Build pipe name: \\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_<PID>
// ============================================================

static void BuildPipeName(char* buf, DWORD pid) {
    myCopyStr(buf, "\\\\.\\pipe\\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_");
    myAppendDword(buf, pid);
}

// ============================================================
// Debug log  — write to C:\Temp\pipe_debug.txt
// ============================================================

static void WriteLog(const char* msg) {
    HANDLE hFile = CreateFileA(
        "C:\\Temp\\pipe_debug.txt",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, msg, myStrLen(msg), &written, NULL);
        WriteFile(hFile, "\r\n", 2, &written, NULL);
        CloseHandle(hFile);
    }
}

// ============================================================
// Pipe server thread
// ============================================================

static DWORD WINAPI PipeThread(LPVOID param) {
    WriteLog("[PipeThread] Starting...");

    DWORD pid = GetCurrentProcessId();
    char pipeName[128];
    BuildPipeName(pipeName, pid);

    WriteLog("[PipeThread] Pipe name:");
    WriteLog(pipeName);

    // Signal that thread is alive
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, "PipeThreadAliveEvent");
    if (hEvent) {
        SetEvent(hEvent);
        // Don't close — keep it signaled for external checkers
    }

    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,       // 3
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, // 0
        10,    // max instances
        4096,  // out buffer
        4096,  // in buffer
        0,     // timeout
        NULL   // security
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        WriteLog("[PipeThread] CreateNamedPipeA FAILED");
        return 1;
    }

    WriteLog("[PipeThread] Pipe created, entering loop...");

    while (1) {
        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            WriteLog("[PipeThread] Client connected");
            // Keep reading/writing until client disconnects
            while (1) {
                // Use small stack buffer (< 4KB to avoid __chkstk_ms)
                char buf[1024];
                DWORD bytesRead = 0;
                BOOL readOk = ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL);
                if (!readOk || bytesRead == 0) break;

                buf[bytesRead] = '\0';
                WriteLog("[PipeThread] Received:");
                WriteLog(buf);

                // Echo back
                DWORD written = 0;
                WriteFile(hPipe, buf, bytesRead, &written, NULL);
            }
            DisconnectNamedPipe(hPipe);
            WriteLog("[PipeThread] Client disconnected");
        }
        Sleep(50);
    }

    CloseHandle(hPipe);
    return 0;
}

// ============================================================
// DllMain — truly CRT-free entry point
// ============================================================

BOOL APIENTRY DllMain(HMODULE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Log that DllMain ran
        WriteLog("[DllMain] DLL_PROCESS_ATTACH");

        // Signal event so external test can verify
        HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, "DllMainRanEvent");
        if (hEvent) {
            SetEvent(hEvent);
            WriteLog("[DllMain] DllMainRanEvent signaled");
        }

        DisableThreadLibraryCalls(hDll);

        // Create pipe thread
        HANDLE hThread = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
        if (hThread) {
            WriteLog("[DllMain] Pipe thread created");
            CloseHandle(hThread);
        } else {
            WriteLog("[DllMain] CreateThread FAILED");
        }
    }
    return TRUE;
}

// Custom entry point that goes directly to DllMain — no CRT init needed
extern "C" BOOL WINAPI _DllMainCRTStartup(HMODULE hDll, DWORD reason, LPVOID reserved) {
    return DllMain(hDll, reason, reserved);
}
