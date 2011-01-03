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
#include "list.h"
#include "pe.h"
#include "mem.h"
#include "render.h"
#include "unicode.h"

#include <string.h>
#include <tchar.h>

PSYSTEM_PROCESS_INFORMATION GetProcessList()
{
    PSYSTEM_PROCESS_INFORMATION pProcessInfo = NULL;
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
    PDWORD pEthreadGuiThread = NULL, pEthread = NULL, pWin32Thread = NULL;    
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
        read_kern_m.src_address = (PVOID)pid;

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

VOID Test()
{
    CheckEATs(NULL, NULL);
}

STATUS_t CheckEATs(FUNC_ARGS_t * args, FUNC_ARGS_GLOBAL_t * globals)
{
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;
    PREPORT_SECTION idSubEat = NULL;
    PSLIST_HEADER pListHead = NULL;
    STATUS_t ret = ST_OK;
    PCHAR pName = NULL;
    BOOL status = FALSE;

    __try
    {
        idSubEat = RenderAddSection("Export Address Table Hooking Detection");
        pProcInfo = GetProcessList();
        if(pProcInfo == NULL)
        {
            OARK_ERROR("GetProcessList failed");
            ret = ST_ERROR;
            goto clean;
        }

        while(pProcInfo->NextEntryOffset != 0)
        {
            pListHead = CheckEATsInProcessContext((DWORD)pProcInfo->ProcessId);
            while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
            {
                pName = PID2ProcessName((DWORD)pHookInfo->other[0]);
                RenderAddSeparator(idSubEat);
                RenderAddEntry(idSubEat, "Ordinal", pHookInfo->id, FORMAT_DEC);
                RenderAddEntry(idSubEat, "Export Name", pHookInfo->other[1], FORMAT_STR_ASCII);
                RenderAddEntry(idSubEat, "Function address", pHookInfo->addr, FORMAT_HEX);
                RenderAddEntry(idSubEat, "DLL Name", pHookInfo->name, FORMAT_STR_ASCII);
                RenderAddEntry(idSubEat, "Process ID", pHookInfo->other[0], FORMAT_HEX);
                RenderAddEntry(idSubEat, "Process Name", pName, FORMAT_STR_ASCII);

                if(pHookInfo->name != NULL)
                    free(pHookInfo->name);

                if(pHookInfo->other[1] != NULL)
                    free(pHookInfo->other[1]);

                if(pName != NULL)
                    free(pName);

                free(pHookInfo);
            }

            if(pListHead != NULL)
                free(pListHead);
            
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD)pProcInfo + pProcInfo->NextEntryOffset);
        }

        clean:
        if(pProcInfo != NULL)
            free(pProcInfo);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return ret;
}

PSLIST_HEADER CheckEATsInProcessContext(DWORD pid)
{
    PIMAGE_EXPORT_DIRECTORY pExpDir = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;
    PIMAGE_DOS_HEADER pImgDos = NULL;
    MODULEENTRY32 mod = {0};
    PSLIST_HEADER pListHead = NULL;
    HANDLE hSnap = NULL;
    PDWORD pAddrFunct = NULL, pName = NULL;
    PSHORT pOrd = NULL;
    DWORD i = 0;
    BOOL ret = TRUE;

    __try
    {
        pListHead = malloc(sizeof(SLIST_HEADER));
        if(pListHead == NULL)
        {
            OARK_ALLOCATION_ERROR();
            goto clean;
        }

        InitializeSListHead(pListHead);

        mod.dwSize = sizeof(MODULEENTRY32);
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if(hSnap == INVALID_HANDLE_VALUE)
        {
            OARK_ERROR("CreateToolhelp32Snapshot failed");
            goto clean;
        }

        if(Module32First(hSnap, &mod) == FALSE)
        {
            OARK_ERROR("Module32First failed");
            goto clean;
        }

        //First is the binary itself, we don't care :)
        while(Module32Next(hSnap, &mod) != FALSE) 
        {
            pExpDir = GetRemoteExportTableDirectory(pid, (DWORD)mod.modBaseAddr);
            if(pExpDir != NULL)
            {
                pAddrFunct = ReadRemoteMemory(pid, 
                    (DWORD)mod.modBaseAddr + pExpDir->AddressOfFunctions,
                    sizeof(DWORD) * pExpDir->NumberOfFunctions
                );

                if(pAddrFunct == NULL)
                {
                    OARK_ALLOCATION_ERROR();
                    ret = FALSE;
                    free(pExpDir);
                    goto clean;
                }
                
                pName = ReadRemoteMemory(pid,
                    (DWORD)mod.modBaseAddr + pExpDir->AddressOfNames,
                    sizeof(DWORD) * pExpDir->NumberOfNames
                );

                if(pName == NULL)
                {
                    OARK_ALLOCATION_ERROR();
                    ret = FALSE;
                    free(pAddrFunct);
                    free(pExpDir);
                    goto clean;
                }

                pOrd = ReadRemoteMemory(pid,
                    (DWORD)mod.modBaseAddr + pExpDir->AddressOfNameOrdinals,
                    sizeof(SHORT) * pExpDir->NumberOfNames
                );

                if(pOrd == NULL)
                {
                    OARK_ALLOCATION_ERROR();
                    ret = FALSE;
                    free(pName);
                    free(pAddrFunct);
                    free(pExpDir);
                    goto clean;
                }

                //Hooked functions exported by ordinal are not detected
                for(i = 0; i < pExpDir->NumberOfNames; ++i)
                {
                    if(pAddrFunct[pOrd[i]] > mod.modBaseSize)
                    {
                        pHookInfo = malloc(sizeof(HOOK_INFORMATION));
                        if(pHookInfo == NULL)
                        {
                            OARK_ALLOCATION_ERROR();
                            ret = FALSE;
                            free(pExpDir);
                            goto clean;
                        }
                        ZeroMemory(pHookInfo, sizeof(HOOK_INFORMATION));

                        pHookInfo->id = pOrd[i] + pExpDir->Base;
                        pHookInfo->addr = (DWORD)mod.modBaseAddr + pAddrFunct[pOrd[i]];
                        pHookInfo->other[0] = (PVOID)pid;
                        pHookInfo->name = UnicodeToAnsi(mod.szModule);

                        if(i < pExpDir->NumberOfNames)
                            pHookInfo->other[1] = ReadRemoteString(pid,
                                (DWORD)mod.modBaseAddr + pName[i]
                            );

                        PushHookInformationEntry(pListHead, pHookInfo);
                    }
                }

                free(pAddrFunct);
                free(pExpDir);
            }
            else
                OARK_ERROR("GetRemoteExportTableDirectory failed");
        }

        clean:
        if(hSnap != NULL)
            CloseHandle(hSnap);

        if(ret == FALSE)
        {
            CleanHookInfoList(pListHead);
            free(pListHead);
            pListHead = NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pListHead;
}