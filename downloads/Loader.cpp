// OWHelperLoader.dll — Tiny loader that loads the real DLL via Windows loader
// Compiled normally with CRT — Windows handles all PE processing
#include <windows.h>

// Export so we can call it if needed
extern "C" __declspec(dllexport) void owlhelper_loader_init() {
    // Load the real executor DLL from within the target process
    LoadLibraryW(L"RobloxExecutorCRT.dll");
}

BOOL APIENTRY DllMain(HMODULE hDll, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Disable thread notifications (we don't need them)
        DisableThreadLibraryCalls(hDll);

        // Load the real DLL — Windows loader handles PE parsing, relocations,
        // CRT initialization, and import resolution automatically
        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID) -> DWORD {
            // Small delay to let the loader finish
            Sleep(100);
            LoadLibraryW(L"RobloxExecutorCRT.dll");
            return 0;
        }, NULL, 0, NULL);

        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
