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
 * @file   process.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Processes stuff.
 *
 */
#include "process.h"
#include "driverusr.h"
#include "unicode.h"

#include <string.h>
#include <tchar.h>

PSYSTEM_PROCESS_INFORMATION GetProcessList()
{
    PSYSTEM_PROCESS_INFORMATION pProcessInfo = NULL, firstValue = NULL;
    NTSTATUS state = 0;
    DWORD size = 0;

    __try
    {
        state = ZwQuerySystemInformation(SystemProcessInformation,
            NULL,
            0,
            &size
        );

        pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)malloc(size);
        if(pProcessInfo == NULL)
        {
            OARK_ALLOCATION_ERROR();
            return NULL;
        }

        state = ZwQuerySystemInformation(SystemProcessInformation,
            pProcessInfo,
            size,
            &size
        );

        if(!NT_SUCCESS(state))
        {
            OARK_ERROR("ZwQuerySystemInformation failed");
            free(pProcessInfo);
            pProcessInfo = NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pProcessInfo;
}

PDWORD GetGUIThread(HANDLE hDevice)
{
    PSYSTEM_PROCESS_INFORMATION pProcessInfos = NULL, pProcessInformation = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    PSYSTEM_THREAD pThread = NULL;
    NTSTATUS ntState = 0;
    PDWORD pEprocess = NULL, pEthreadGuiThread = NULL, pEthread = NULL, pSsdtSystem = NULL, pWin32Thread = NULL;    
    DWORD i = 0;

    __try
    {
        if(Offsets.isSupported == FALSE)
        {
            OARK_ERROR("This function requires offsets support");
            return NULL;
        }

        pProcessInfos = GetProcessList();
        if(pProcessInfos == NULL)
        {
            OARK_ERROR("GetProcessList failed");
            return NULL;
        }

        pProcessInformation = pProcessInfos;

        while(pProcessInfos->NextEntryOffset != 0)
        {
            if(pProcessInfos->ImageName.Buffer != NULL)
            {
                for(i = 0; i < pProcessInfos->NumberOfThreads; ++i) 
                {     
                    pEthread = GetETHREADStructureByTid(hDevice, (DWORD)(pProcessInfos->Threads[i].ClientId.UniqueThread));
                    if(pEthread == NULL)
                    {
                        OARK_ERROR("GetETHREADStructureByTid failed");
                        free(pProcessInformation);
                        return NULL;
                    }

                    read_kern_m.dst_address = &pWin32Thread;
                    read_kern_m.src_address = (PVOID)((DWORD)pEthread + Offsets.KTHREADWin32Thread);
                    read_kern_m.size = sizeof(DWORD);
                    read_kern_m.type = SYM_TYP_NULL;

                    if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
                    {
                        OARK_IOCTL_ERROR();
                        free(pProcessInformation);
                        return NULL;
                    }

                    if(pWin32Thread != NULL)
                    {
                        pEthreadGuiThread = pEthread;
                        break;
                    }
                }

                if(pEthreadGuiThread != NULL)
                    break;
            }

            pProcessInfos = (PSYSTEM_PROCESS_INFORMATION)((((DWORD)pProcessInfos) + pProcessInfos->NextEntryOffset));
        }

        free(pProcessInformation);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pEthreadGuiThread;
}

PDWORD GetETHREADStructureByTid(HANDLE hDevice, DWORD threadID)
{
    READ_KERN_MEM_t read_kern_mem = {0};
    PDWORD pEthread = NULL;

    __try
    {
        read_kern_mem.type = SYM_TYP_PSLOUTHBYID;
        read_kern_mem.src_address = (PVOID)threadID;
        read_kern_mem.dst_address = &pEthread;
        read_kern_mem.size = sizeof(PDWORD);

        if(IOCTLReadKernMem(hDevice, &read_kern_mem) == NULL)
        {
            OARK_IOCTL_ERROR();
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
    
    return pEthread;
}

PDWORD Ethread2Eprocess(HANDLE hDevice, PDWORD pEthread)
{
    READ_KERN_MEM_t read_kern_m = {0};
    PDWORD pEprocess = 0;

    __try
    {
        if(Offsets.isSupported == FALSE)
        {
            OARK_ERROR("This function requires offset support");
            return NULL;
        }

        read_kern_m.dst_address = &pEprocess;
        read_kern_m.size = sizeof(PDWORD);
        read_kern_m.src_address = (PVOID)((DWORD)pEthread + Offsets.ETHREAD2Eprocess);
        read_kern_m.type = SYM_TYP_NULL;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            OARK_IOCTL_ERROR();
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pEprocess;
}

PDWORD PID2Eprocess(HANDLE hDevice, DWORD pid)
{
    READ_KERN_MEM_t read_kern_m = {0};
    PDWORD pEprocess = NULL;

    __try
    {
        read_kern_m.dst_address = &pEprocess;
        read_kern_m.size = sizeof(DWORD);
        read_kern_m.type = SYM_TYP_PSLOUPRBYID;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
            OARK_IOCTL_ERROR();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pEprocess;
}

PCHAR PID2ProcessName(DWORD pid)
{
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL, pProc = NULL;
    PCHAR pName = NULL;
    DWORD sizeStr = 0;

    __try
    {
        pProcInfo = (pProc = GetProcessList());
        if(pProcInfo == NULL)
        {
            OARK_ERROR("GetProcessList failed");
            goto clean;
        }

        while(pProc->NextEntryOffset)
        {
            if((DWORD)pProc->ProcessId == pid)
            {
                pName = UnicodeToAnsi(pProc->ImageName.Buffer);
                break;
            }
            pProc = (PSYSTEM_PROCESS_INFORMATION)((DWORD)pProc + pProc->NextEntryOffset);
        }

        clean:
        if(pProcInfo != NULL)
            free(pProcInfo);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pName;
}