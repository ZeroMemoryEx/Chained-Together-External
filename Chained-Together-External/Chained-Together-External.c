#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <psapi.h>  // For EnumProcessModules, GetModuleInformation
#include <tchar.h>  // For _tcsicmp

#pragma comment(lib, "psapi.lib")  // Link against PSAPI library

// Pattern to search for in memory
unsigned char pattern[] = { 0xF2, 0x43, 0x0F, 0x11, 0x44, 0xDA, 0x10 };

// Our hook code that will replace the pattern - using JMP only, with NOPs to fill remaining bytes
unsigned char hookCode[] = {
    0xE9, 0x00, 0x00, 0x00, 0x00,  // jmp relative_address (5 bytes)
    0x90, 0x90                     // 2 NOPs to pad to 7 bytes (original instruction size)
};

// Our custom values
float our_values[4] = { 0.10f, 9.41f, 0.00f, 0.00f };

// Function to find the process ID by name
DWORD GetProcessIdByName(const char* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &processEntry)) {
            do {
                // Convert process name to char* for comparison
                char exeFile[MAX_PATH];
                wcstombs(exeFile, processEntry.szExeFile, MAX_PATH);

                if (_stricmp(exeFile, processName) == 0) {
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

// Function to find pattern in memory
LPVOID FindPattern(HANDLE hProcess, LPVOID startAddress, LPVOID endAddress, unsigned char* pattern, size_t patternSize) {
    const size_t BUFFER_SIZE = 4096;
    unsigned char buffer[4096];
    LPVOID currentAddress = startAddress;

    while (currentAddress < endAddress) {
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, currentAddress, buffer, BUFFER_SIZE, &bytesRead) || bytesRead == 0) {
            break;
        }

        for (size_t i = 0; i < bytesRead - patternSize; i++) {
            BOOL found = 1;
            for (size_t j = 0; j < patternSize; j++) {
                if (buffer[i + j] != pattern[j]) {
                    found = 0;
                    break;
                }
            }

            if (found) {
                return (LPBYTE)currentAddress + i;
            }
        }

        currentAddress = (LPBYTE)currentAddress + (bytesRead - patternSize);
    }

    return NULL;
}

// Function to scan module for pattern
LPVOID ScanModuleForPattern(HANDLE hProcess, const char* moduleName, unsigned char* pattern, size_t patternSize) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    MODULEINFO moduleInfo;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModNameW[MAX_PATH];
            char szModName[MAX_PATH];

            if (GetModuleFileNameExW(hProcess, hMods[i], szModNameW, sizeof(szModNameW) / sizeof(WCHAR))) {
                // Convert wide string to multibyte
                WideCharToMultiByte(CP_ACP, 0, szModNameW, -1, szModName, MAX_PATH, NULL, NULL);

                if (strstr(szModName, moduleName)) {
                    GetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof(moduleInfo));
                    return FindPattern(hProcess, moduleInfo.lpBaseOfDll,
                        (LPBYTE)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage,
                        pattern, patternSize);
                }
            }
        }
    }

    return NULL;
}

// Function to allocate memory near a specific address (within 2GB range)
LPVOID AllocateNearMemory(HANDLE hProcess, LPVOID targetAddress) {
    // Try to allocate memory close to the target address (within 2GB)
    const UINT64 TWO_GB = 0x80000000;
    UINT64 minAddr = (UINT64)targetAddress > TWO_GB ? (UINT64)targetAddress - TWO_GB : 0;
    UINT64 maxAddr = (UINT64)targetAddress + TWO_GB;

    // Try with increasingly larger ranges if needed
    for (UINT64 rangeSize = 0x10000; rangeSize <= TWO_GB; rangeSize *= 2) {
        MEMORY_BASIC_INFORMATION mbi;
        UINT64 currentAddr = max(minAddr, (UINT64)targetAddress - rangeSize);
        UINT64 endAddr = min(maxAddr, (UINT64)targetAddress + rangeSize);

        while (currentAddr < endAddr) {
            if (VirtualQueryEx(hProcess, (LPVOID)currentAddr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= 4096) {
                    LPVOID allocatedMem = VirtualAllocEx(hProcess, mbi.BaseAddress, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (allocatedMem) {
                        return allocatedMem;
                    }
                }
                currentAddr = (UINT64)mbi.BaseAddress + mbi.RegionSize;
            }
            else {
                currentAddr += 4096;
            }
        }
    }

    // If we couldn't allocate near memory, fall back to normal allocation
    return VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

int main() {
    const char* processName = "ChainedTogether-Win64-Shipping.exe";
    DWORD pid = GetProcessIdByName(processName);

    if (pid == 0) {
        printf("Process '%s' not found\n", processName);
        return 1;
    }

    printf("Found process '%s' with PID: %u\n", processName, pid);

    // Open the process with required access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open process. Error: %u\n", GetLastError());
        return 1;
    }

    // Find the pattern in memory
    LPVOID patternAddress = ScanModuleForPattern(hProcess, processName, pattern, sizeof(pattern));
    if (patternAddress == NULL) {
        printf("Pattern not found in process memory\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("Pattern found at address: 0x%p\n", patternAddress);

    // Try to allocate memory near the target address to use relative jumps
    LPVOID codeMemory = AllocateNearMemory(hProcess, patternAddress);
    LPVOID dataMemory = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (codeMemory == NULL || dataMemory == NULL) {
        printf("Failed to allocate memory. Error: %u\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    printf("Allocated code memory at: 0x%p\n", codeMemory);
    printf("Allocated data memory at: 0x%p\n", dataMemory);

    // Write our custom values to data memory
    if (!WriteProcessMemory(hProcess, dataMemory, our_values, sizeof(our_values), NULL)) {
        printf("Failed to write data. Error: %u\n", GetLastError());
        VirtualFreeEx(hProcess, codeMemory, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, dataMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create our assembly code - Properly executes the original instruction then returns
    unsigned char asmCode[] = {
        // Save registers we'll use (RAX might be important)
        0x50,                                                       // push rax
        0x51,                                                       // push rcx

        // Move data address to rcx and load our custom values to xmm0
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, dataMemory
        0x0F, 0x28, 0x01,                                           // movaps xmm0, [rcx]

        // Apply our custom values
        0xF2, 0x43, 0x0F, 0x11, 0x44, 0xDA, 0x10,                   // movsd [r10+r11*8+10], xmm0

        // Restore saved registers
        0x59,                                                       // pop rcx
        0x58,                                                       // pop rax

        // Jump back to original code path (right after our hook)
        0xE9, 0x00, 0x00, 0x00, 0x00                               // jmp back to original code
    };

    // Calculate the size of our assembly code
    const size_t codeSize = sizeof(asmCode);
    printf("Code size: %zu bytes\n", codeSize);

    // Calculate offsets for the jump instructions
    INT32 returnOffset = (INT32)((UINT64)patternAddress + sizeof(pattern) - ((UINT64)codeMemory + codeSize - 4));
    INT32 hookOffset = (INT32)((UINT64)codeMemory - ((UINT64)patternAddress + 5));

    printf("Hook offset: 0x%X\n", hookOffset);
    printf("Return offset: 0x%X\n", returnOffset);

    // Set the addresses in the code
    *(UINT64*)(asmCode + 4) = (UINT64)dataMemory;
    *(INT32*)(asmCode + codeSize - 4) = returnOffset;

    // Set the jump offset in the hook code
    *(INT32*)(hookCode + 1) = hookOffset;

    // Write our assembly code to memory
    if (!WriteProcessMemory(hProcess, codeMemory, asmCode, codeSize, NULL)) {
        printf("Failed to write code. Error: %u\n", GetLastError());
        VirtualFreeEx(hProcess, codeMemory, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, dataMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Backup original bytes
    unsigned char originalBytes[sizeof(pattern)];
    if (!ReadProcessMemory(hProcess, patternAddress, originalBytes, sizeof(originalBytes), NULL)) {
        printf("Failed to backup original bytes. Error: %u\n", GetLastError());
        VirtualFreeEx(hProcess, codeMemory, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, dataMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Write the hook code
    DWORD oldProtect;
    VirtualProtectEx(hProcess, patternAddress, sizeof(hookCode), PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!WriteProcessMemory(hProcess, patternAddress, hookCode, sizeof(hookCode), NULL)) {
        printf("Failed to write hook code. Error: %u\n", GetLastError());
        VirtualProtectEx(hProcess, patternAddress, sizeof(hookCode), oldProtect, NULL);
        VirtualFreeEx(hProcess, codeMemory, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, dataMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    VirtualProtectEx(hProcess, patternAddress, sizeof(hookCode), oldProtect, NULL);

    printf("Injection successful!\n");
    printf("Press Enter to restore original code and exit...\n");
    getchar();

    // Restore original bytes when done
    VirtualProtectEx(hProcess, patternAddress, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, patternAddress, originalBytes, sizeof(originalBytes), NULL);
    VirtualProtectEx(hProcess, patternAddress, sizeof(originalBytes), oldProtect, NULL);

    // Free allocated memory
    VirtualFreeEx(hProcess, codeMemory, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, dataMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("Original code restored. Exiting...\n");
    return 0;
}
