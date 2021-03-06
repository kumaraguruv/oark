/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>
Copyright (c) <2010> <0vercl0k aka Souchet Axel, 0vercl0k@tuxfamily.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef __OTHERS_H__
#define __OTHERS_H__

#include <windows.h>
#include <tlhelp32.h>
#include "common.h"
#include "debug.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) 
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _OFFSETS
{
	BOOLEAN isSupported;

	DWORD VAD_ROOT;
    DWORD KTHREADWin32Thread;
    DWORD KTHREADServiceTable;
    DWORD ETHREAD2Eprocess;

    PCHAR *pGuiSyscallName;
} OFFSETS;

OFFSETS Offsets;


typedef LPVOID         *PPVOID;

typedef struct _PEB_FREE_BLOCK 
{
	struct _PEB_FREE_BLOCK *Next; 
	ULONG Size;

} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef void (*PPEBLOCKROUTINE) (PVOID PebLock);

typedef struct _UNICODE_STRING 
{
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;

} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _RTL_DRIVE_LETTER_CURDIR 
{
	USHORT Flags; 
	USHORT Length; 
	ULONG TimeStamp; 
	UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS 
{
	ULONG MaximumLength; 
	ULONG Length; 
	ULONG Flags; 
	ULONG DebugFlags; 
	PVOID ConsoleHandle; 
	ULONG ConsoleFlags; 
	HANDLE StdInputHandle; 
	HANDLE StdOutputHandle; 
	HANDLE StdErrorHandle; 
	UNICODE_STRING CurrentDirectoryPath; 
	HANDLE CurrentDirectoryHandle; 
	UNICODE_STRING DllPath; 
	UNICODE_STRING ImagePathName; 
	UNICODE_STRING CommandLine; 
	PVOID Environment; 
	ULONG StartingPositionLeft; 
	ULONG StartingPositionTop; 
	ULONG Width; ULONG Height; 
	ULONG CharWidth; 
	ULONG CharHeight; 
	ULONG ConsoleTextAttributes; 
	ULONG WindowFlags; 
	ULONG ShowWindowFlags; 
	UNICODE_STRING WindowTitle; 
	UNICODE_STRING DesktopName; 
	UNICODE_STRING ShellInfo; 
	UNICODE_STRING RuntimeData; 
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];

} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA 
{
	ULONG Length; 
	BOOLEAN Initialized; 
	PVOID SsHandle; 
	LIST_ENTRY InLoadOrderModuleList; 
	LIST_ENTRY InMemoryOrderModuleList; 
	LIST_ENTRY InInitializationOrderModuleList;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE 
{
	LIST_ENTRY InLoadOrderModuleList; 
	LIST_ENTRY InMemoryOrderModuleList; 
	LIST_ENTRY InInitializationOrderModuleList; 
	PVOID BaseAddress; 
	PVOID EntryPoint; 
	ULONG SizeOfImage; 
	UNICODE_STRING FullDllName; 
	UNICODE_STRING BaseDllName; 
	ULONG Flags; 
	SHORT LoadCount; 
	SHORT TlsIndex; 
	LIST_ENTRY HashTableEntry; 
	ULONG TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB 
{   
	BOOLEAN InheritedAddressSpace    ; 
	BOOLEAN ReadImageFileExecOptions ; 
	BOOLEAN BeingDebugged            ; 
	BOOLEAN Spare                    ; 
	HANDLE  Mutant                   ; 
	PVOID ImageBaseAddress           ; 
	PPEB_LDR_DATA LoaderData         ; 
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters; 
	PVOID SubSystemData; 
	PVOID ProcessHeap; 
	PVOID FastPebLock; 
	PPEBLOCKROUTINE FastPebLockRoutine; 
	PPEBLOCKROUTINE FastPebUnlockRoutine; 
	ULONG EnvironmentUpdateCount; 
	PPVOID KernelCallbackTable; 
	PVOID EventLogSection; 
	PVOID EventLog; 
	PPEB_FREE_BLOCK FreeList; 
	ULONG TlsExpansionCounter; 
	PVOID TlsBitmap; 
	ULONG TlsBitmapBits[0x2]; 
	PVOID ReadOnlySharedMemoryBase; 
	PVOID ReadOnlySharedMemoryHeap; 
	PPVOID ReadOnlyStaticServerData;
	PVOID AnsiCodePageData; 
	PVOID OemCodePageData; 
	PVOID UnicodeCaseTableData; 
	ULONG NumberOfProcessors; 
	ULONG NtGlobalFlag; 
	BYTE Spare2[0x4]; 
	LARGE_INTEGER CriticalSectionTimeout; 
	ULONG HeapSegmentReserve; 
	ULONG HeapSegmentCommit; 
	ULONG HeapDeCommitTotalFreeThreshold; 
	ULONG HeapDeCommitFreeBlockThreshold; 
	ULONG NumberOfHeaps; 
	ULONG MaximumNumberOfHeaps; 
	PPVOID *ProcessHeaps; 
	PVOID GdiSharedHandleTable; 
	PVOID ProcessStarterHelper; 
	PVOID GdiDCAttributeList; 
	PVOID LoaderLock; 
	ULONG OSMajorVersion; 
	ULONG OSMinorVersion; 
	ULONG OSBuildNumber; 
	ULONG OSPlatformId; 
	ULONG ImageSubSystem; 
	ULONG ImageSubSystemMajorVersion; 
	ULONG ImageSubSystemMinorVersion; 
	ULONG GdiHandleBuffer[0x22]; 
	ULONG PostProcessInitRoutine; 
	ULONG TlsExpansionBitmap; 
	BYTE TlsExpansionBitmapBits[0x80]; 
	ULONG SessionId;

} PEB, *PPEB;


typedef LONG 	NTSTATUS;

typedef enum  _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation
    /* [...] */
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS 
{ 
    ProcessBasicInformation 
} PROCESSINFOCLASS;

typedef NTSTATUS 
(WINAPI * ZWQUERYINFORMATIONPROCESS_t)
(
 HANDLE, 
 PROCESSINFOCLASS, 
 PVOID, 
 ULONG, 
 PULONG
 ); 

typedef NTSTATUS 
(WINAPI *ZWQUERYSYSTEMINFORMATION_t)(
    ULONG,
    PVOID,
    ULONG,
    PULONG
);

typedef struct _PROCESS_BASIC_INFORMATION 
{
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;

} PROCESS_BASIC_INFORMATION;

typedef struct FUNC_ARGS_GLOBAL_s
{
    HANDLE * hdevice;

} FUNC_ARGS_GLOBAL_t;

typedef struct FUNC_ARGS_s
{
    DWORD flags;

} FUNC_ARGS_t;

typedef struct _KIDTENTRY
{
    WORD Offset;
    WORD Selector;
    WORD Access;
    WORD ExtendedOffset;
} KIDTENTRY, *PKIDTENTRY;

typedef struct _KGDTENTRY
{
    WORD LimitLow;
    WORD BaseLow;
    ULONG HighWord;
} KGDTENTRY, *PKGDTENTRY;

typedef struct _KPCR
{
    NT_TIB NtTib;   /* FIXED UNION: I AM NOT INTERESTED IN THIS */
    void * SelfPcr; /* FIXED: I AM NOT INTERESTED IN THIS */
    void * Prcb;    /* FIXED: I AM NOT INTERESTED IN THIS */
    UCHAR Irql;
    ULONG IRR;
    ULONG IrrActive;
    ULONG IDR;
    PVOID KdVersionBlock;
    PKIDTENTRY IDT;
    PKGDTENTRY GDT;

    /* ... */
} KPCR, *PKPCR;

ZWQUERYINFORMATIONPROCESS_t ZwQueryInformationProcess;
ZWQUERYSYSTEMINFORMATION_t ZwQuerySystemInformation;

STATUS_t LockInstance( DWORD * );
BOOLEAN DumpRSRC( char *, int, char * );
BOOLEAN GetFullTempPath( char **, char * );
STATUS_t Init( void );
void CheckOSVersion( void );

#endif /* __OTHERS_H__ */