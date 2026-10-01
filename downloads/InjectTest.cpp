#include <windows.h>
#include <stdio.h>

// Test DLL that just writes to a file when loaded
BOOL APIENTRY DllMain(HMODULE hDll, DWORD reason, LPVOID reserved) {
    char buf[512];
    DWORD pid = GetCurrentProcessId();
    sprintf(buf, "C:\\Temp\\injection_test_%lu.txt", pid);
    
    FILE* f = fopen(buf, "a");
    if (f) {
        fprintf(f, "DllMain called: reason=%lu, pid=%lu, hDll=%p\n", reason, pid, hDll);
        fclose(f);
    }
    
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
    }
    
    return TRUE;
}

// Export to verify the DLL is valid
extern "C" __declspec(dllexport) void test_export() {}
