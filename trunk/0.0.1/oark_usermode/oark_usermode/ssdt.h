/*
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

/**
 * @file   ssdt.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   November, 2010
 * @brief  SSDT Hooking stuff.
 *
 * Thanks to Ivanlef0u for his review :).
 */

#ifndef _SSDT_H_
#define _SSDT_H_

#include <windows.h>
#include <stdio.h>

#include "others.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

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

#pragma pack(1)
typedef struct
{
    PULONG Base;
    PULONG Count;
    ULONG Limit;
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
#pragma pack()

typedef struct
{
    ULONG Reserved1;
    ULONG Reserved2;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    WORD Id;
    WORD Rank;
    WORD w018;
    WORD NameOffset;
    BYTE Name[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

#pragma warning(disable:4200)
typedef struct
{
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LONG KPRIORITY;

typedef enum
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    Spare2,
    Spare3,
    Spare4,
    Spare5,
    Spare6,
    WrKernel,
    MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD 
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG State;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _VM_COUNTERS 
{
    DWORD PeakVirtualSize;
    DWORD VirtualSize;
    DWORD PageFaultCount;
    DWORD PeakWorkingSetSize;
    DWORD WorkingSetSize;
    DWORD QuotaPeakPagedPoolUsage;
    DWORD QuotaPagedPoolUsage;
    DWORD QuotaPeakNonPagedPoolUsage;
    DWORD QuotaNonPagedPoolUsage;
    DWORD PagefileUsage;
    DWORD PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION 
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    VM_COUNTERS VirtualMemoryCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


typedef struct
{
    SLIST_ENTRY SListEntry;
    DWORD idSyscall;
    DWORD functionHook;
    PCHAR nameOfHooker;
}HOOK_INFORMATION, *PHOOK_INFORMATION;

/**
 * @name    CheckSSDTHooking
 * @brief   Check SSDTs structures.
 *
 * This API search and displays potential hook in SSDTs structures.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * Example Usage:
 * @code
 *    CheckSSDTHooking(hDevice);
 * @endcode
 */
VOID CheckSSDTHooking(HANDLE hDevice);

/**
 * @name    GetSsdtSystemStructure
 * @brief   Retrieves SSDT System structure.
 *
 * This API gives SSDT System structure.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a KSERVICE_TABLE_DESCRIPTOR structure.
 *
 * Example Usage:
 * @code
 *    GetSsdtSystemStructure(hDevice); //Never forgotten to free pointer
 * @endcode
 */
PKSERVICE_TABLE_DESCRIPTOR GetSsdtSystemStructure(HANDLE hDevice);

/**
 * @name    GetSsdtShadowStructure
 * @brief   Retrieves SSDT Shadow structure.
 *
 * This API gives SSDT Shadow structure.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a KSERVICE_TABLE_DESCRIPTOR structure.
 *
 * Example Usage:
 * @code
 *    GetSsdtShadowStructure(hDevice); //Never forgotten to free pointer
 * @endcode
 */
PKSERVICE_TABLE_DESCRIPTOR GetSsdtShadowStructure(HANDLE hDevice);

/**
 * @name    SsdtSystemHookingDetection
 * @brief   This routine returns information about hooked SSDT System entries.
 *
 * This API gives informations relative to hooked SSDT System entries.
 * NB : To manipulate SLIST_ENTRY use PopHookInformationList/PushHookInformationList
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to SLIST_HEADER structure, the head of the single linked list.
 *
 * Example Usage:
 * @code
 *    SsdtSystemHookingDetection(hDevice); 
 *    // /!\ Never forgotten to clean the list with PopInformationHookList and free for the 'name' field.
 * @endcode
 */
PSLIST_HEADER SsdtSystemHookingDetection(HANDLE hDevice);

/**
 * @name    SsdtShadowHookingDetection
 * @brief   This routine returns information about hooked SSDT Shadow entries.
 *
 * This API gives informations relative to hooked SSDT Shadow entries.
 * NB : To manipulate SLIST_ENTRY use PopHookInformationList/PushHookInformationList
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to SLIST_HEADER structure, the head of the single linked list.
 *
 * Example Usage:
 * @code
 *    SsdtShadowHookingDetection(hDevice); 
 *    // /!\ Never forgotten to clean the list with PopInformationHookList and free for the 'name' field.
 * @endcode
 */
PSLIST_HEADER SsdtShadowHookingDetection(HANDLE hDevice);

/**
 * @name    SsdtHookingDetection
 * @brief   This routine returns information about hooked SSDT entries.
 *
 * This API gives informations relative to hooked SSDT entries.
 * NB : To manipulate SLIST_HEADER use PopHookInformationList/PushHookInformationList
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 * @param [in] pSsdt A pointer to an KSERVICE_TABLE_DESCRIPTOR.
 * @param [in] pFunctSsdt  A pointer to an array of SSDT entries.
 * @param [in] modBase The base address of module which exported functions contained in pSsdt.
 * @param [in] modSize The image size o this module.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to SLIST_HEADER structure, the head of the single linked list.
 *
 * Example Usage:
 * @code
 *    SsdtHookingDetection(hdevice, pSsdtAddress, pSsdtAddress->modBase, pSsdtAddress->modSize); 
 *    // /!\ Never forgotten to clean the list with PopInformationHookList and free for the 'name' field.
 * @endcode
 */
PSLIST_HEADER SsdtHookingDetection(HANDLE hDevice, PKSERVICE_TABLE_DESCRIPTOR pSsdt, PDWORD pFunctSsdt, DWORD modBase, DWORD modSize);

/**
 * @name    PushHookInformationEntry
 * @brief   This routine allows you to push an HOOK_INFORMATION structure from a list.
 *
 * This API pops a structure HOOK_INFORMATION from the single linked list.
 *
 * @param [in] pListHead  A pointer to a SLIST_ENTRY which is the single linked list's head.
 * @param [in] entry  A pointer to a HOOK_INFORMATION structure.
 *
 * Example Usage:
 * @code
 *    PushHookInformationEntry(pListHead, pHookInfo); 
 * @endcode
 */
VOID PushHookInformationEntry(PSLIST_HEADER pListHead, PHOOK_INFORMATION entry);

/**
 * @name    PopHookInformationEntry
 * @brief   This routine allows you to pop an HOOK_INFORMATION structure from a list.
 *
 * This API pops a structure HOOK_INFORMATION from the single linked list.
 *
 * @param [in] pListHead  A pointer to a SLIST_ENTRY which is the single linked list's head.
 *
 * @retval NULL  The list is empty.
 * @retval other  A pointer to the driver name.
 *
 * Example Usage:
 * @code
 *    PHOOK_INFORMATION pHook = PopHookInformationEntry(pListHead); 
 *    // /!\ Never forgotten to free the pointer and the 'name' field.
 * @endcode
 */
PHOOK_INFORMATION PopHookInformationEntry(PSLIST_HEADER pListHead);

/**
 * @name    IsAddressInADriver
 * @brief   This routine returns name of the driver in which pFunct is pointing.
 *
 * This API is useful to know which module hooked an SSDT entry.
 *
 * @param [in] pFunct  Address of the function.
 *
 * @retval NULL  Driver name is unknown.
 * @retval other  A pointer to the driver name.
 *
 * Example Usage:
 * @code
 *    IsAddressInADriver(0x1337); // /!\ Never forgotten to free the pointer.
 * @endcode
 */
PCHAR IsAddressInADriver(DWORD pFunct);

/**
 * @name    GetKernelModuleInformation
 * @brief   This routine returns information concerning the kernel module.
 *
 * This API gives many informations relative to the kernel module.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a SYSTEM_MODULE structure.
 *
 * Example Usage:
 * @code
 *    GetKernelModuleInformation(); //Never forgotten to free the pointer !
 * @endcode
 */
PSYSTEM_MODULE GetKernelModuleInformation();

/**
 * @name    GetWin32kModuleInformation
 * @brief   This routine returns information concerning the win32k module.
 *
 * This API gives many informations relative to the kernel module.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a SYSTEM_MODULE structure.
 *
 * Example Usage:
 * @code
 *    GetKernelModuleInformation(); //Never forgotten to free the pointer !
 * @endcode
 */
PSYSTEM_MODULE GetWin32kModuleInformation();

/**
 * @name    GetModuleInformation
 * @brief   This routine returns information concerning a module.
 *
 * This API gives many informations relative to a module.
 *
 * @param [in] pModuleName Module name to search.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a SYSTEM_MODULE structure.
 *
 * Example Usage:
 * @code
 *    GetModuleInformation("amodule.sys"); //Never forgotten to free the pointer !
 * @endcode
 */
PSYSTEM_MODULE GetModuleInformation(PCHAR pModuleName);

/**
 * @name    GetModuleList
 * @brief   You can retrieve the list of modules ran in the system.
 *
 * This API gives the list of system modules loaded on the system.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a SYSTEM_MODULE_INFORMATION structure.
 *
 * Example Usage:
 * @code
 *    GetModuleList(); //Never forgotten to FreePool the pointer !
 * @endcode
 */
PSYSTEM_MODULE_INFORMATION GetModuleList();

/**
 * @name    GetProcessList
 * @brief   Retrieve information relative to process ran on the system
 *
 * This API gives the list of process ran on the the system.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a SYSTEM_MODULE_INFORMATION structure.
 *
 * Example Usage:
 * @code
 *    GetProcessList(); //Never forgotten to free the pointer !
 * @endcode
 */
PSYSTEM_PROCESS_INFORMATION GetProcessList();

/**
 * @name    GetETHREADStructureByTid
 * @brief   This routine returns a pointer to the ETHREAD structure of a thread.
 *
 * This API gives a pointer to the ETHREAD structure relative a thread-id.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 * @param [in] threadID Thread-ident.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to an ETHREAD structure.
 *
 * Example Usage:
 * @code
 *    GetETHREADStructureByTid(hDevice, tId); 
 * @endcode
 */
PDWORD GetETHREADStructureByTid(HANDLE hDevice, DWORD threadID);

/**
 * @name    GetGUIThread
 * @brief   This routine returns a pointer to an ETHREAD GUI structure.
 *
 * This API gives you a pointer on an ETHREAD of a GUI-thread.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to an ETHREAD structure.
 *
 * Example Usage:
 * @code
 *    GetGUIThread(hDevice);
 * @endcode
 */
PDWORD GetGUIThread(HANDLE hDevice);

/**
 * @name    Ethread2Eprocess
 * @brief   This routine returns a pointer to an EPROCESS structure relative to ETHREAD.
 *
 * This API gives you a pointer on an EPROCESS based on an ETHREAD structure.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 * @param [in] pEthread Pointer to an ETHREAD structure.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to an EPROCESS structure.
 *
 * Example Usage:
 * @code
 *    Ethread2Eprocess(pEthread);
 * @endcode
 */
PDWORD Ethread2Eprocess(HANDLE hDevice, PDWORD pEthread);

#endif