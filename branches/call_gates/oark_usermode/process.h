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
 * @file   process.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Processes stuff.
 *
 */

#ifndef _PROCESS_H_
#define _PROCESS_H_

#include "others.h"

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