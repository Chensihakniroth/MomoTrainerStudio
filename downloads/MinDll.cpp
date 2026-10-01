// Minimal DLL - test by creating a file
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Try to create a file using raw Win32 API
        HANDLE hFile = CreateFileA(
            "C:\\Users\\Niroth\\Documents\\dll_main_test.txt",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            const char msg[] = "DllMain was called!";
            WriteFile(hFile, msg, sizeof(msg) - 1, &written, NULL);
            CloseHandle(hFile);
        }
    }
    return TRUE;
}
