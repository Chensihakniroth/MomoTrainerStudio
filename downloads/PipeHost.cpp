// PipeHost.cpp — console host that LoadLibraryW's an executor DLL.
//
// Purpose: test the executor's pipe contract WITHOUT Roblox.
// The DLL's DllMain starts its named-pipe server; this host owns the
// process, so a failure here is attributable to the DLL or the pipe
// name, not to injection, anti-cheat, or a loaded game place.
//
// Prints its own PID on stdout (NOT the launcher's PID — see the note
// in tests/test_pipe_roundtrip.py about shim processes), then waits.
//
// Build:
//   powershell -NoProfile -ExecutionPolicy Bypass -File tools\msvc_build.ps1 \
//       -Source downloads\PipeHost.cpp -Output downloads\PipeHost.exe

#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: PipeHost.exe <dll path>\n");
        fflush(stdout);
        return 2;
    }

    // Convert to wide for LoadLibraryW.
    int wlen = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, NULL, 0);
    if (wlen <= 0) {
        printf("ERROR bad path\n");
        fflush(stdout);
        return 1;
    }
    wchar_t* wdll = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, wlen * sizeof(wchar_t));
    if (!wdll) { printf("ERROR oom\n"); fflush(stdout); return 1; }
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wdll, wlen);

    // Report the PID we actually own, on its own line, before loading.
    printf("%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);

    HMODULE h = LoadLibraryW(wdll);
    if (!h) {
        printf("ERROR LoadLibraryW failed err=%lu\n", (unsigned long)GetLastError());
        fflush(stdout);
        HeapFree(GetProcessHeap(), 0, wdll);
        return 1;
    }

    printf("LOADED %p\n", (void*)h);
    fflush(stdout);

    // Keep the process alive so the DLL's pipe server thread keeps running.
    // The DLL is never freed: closing it would tear down the pipe mid-test.
    for (;;) Sleep(500);

    // unreachable
    return 0;
}