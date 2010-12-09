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
 * @file   ssdt.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   November, 2010
 * @brief  SSDT Hooking stuff.
 *
 */

#include "ssdt.h"
#include "common.h"
#include "driverusr.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>

VOID CheckSSDTHooking(HANDLE hDevice)
{
    PSLIST_HEADER pListHead = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;
    PKSERVICE_TABLE_DESCRIPTOR pSsdt = NULL;

    pListHead = SsdtSystemHookingDetection(hDevice);
    if(pListHead == NULL)
    {
        DisplayErrorMsg("The list is empty");
        return;
    }

    pSsdt = GetSsdtSystemStructure(hDevice);
    if(pSsdt == NULL)
        return;

    printf(" INFO: SSDT System Hook Information (0x%.8x):\n", pSsdt->Base);
    free(pSsdt);

    while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
    {
        printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n Hooker driver: %s", pHookInfo->idSyscall, pHookInfo->functionHook, pHookInfo->nameOfHooker);
        if(pHookInfo->nameOfHooker != NULL)
            free(pHookInfo->nameOfHooker);
        free(pHookInfo);
    }
    printf("\n\n");
    free(pListHead);

    pSsdt = GetSsdtShadowStructure(hDevice);
    if(pSsdt == NULL)
        return;

    pListHead = SsdtShadowHookingDetection(hDevice);
    if(pListHead == NULL)
    {
        DisplayErrorMsg("The list is empty");
        return;
    }

    printf(" INFO: SSDT Shadow functions are at 0x%.8X\n", pSsdt->Base);
    free(pSsdt);
    while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
    {
        printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n Hooker driver: %s", pHookInfo->idSyscall, pHookInfo->functionHook, pHookInfo->nameOfHooker);
        if(pHookInfo->nameOfHooker != NULL)
            free(pHookInfo->nameOfHooker);
        free(pHookInfo);
    }
    printf("\n\n");
    free(pListHead);
}


PSLIST_HEADER SsdtShadowHookingDetection(HANDLE hDevice)
{
    PSLIST_HEADER pListHead = NULL;
    PSYSTEM_MODULE pWin32kInfo = NULL;
    PKSERVICE_TABLE_DESCRIPTOR pShadowSSDT = NULL;
    PDWORD pEprocessWithGuiThread = NULL, pEthreadGui = NULL, pFunctShadowSSDT = NULL;
    READ_KERN_MEM_t read_kern_m = {0};

    __try
    {
        pWin32kInfo = GetWin32kModuleInformation();
        if(pWin32kInfo == NULL)
        {
            DisplayErrorMsg("Couldn't retrieve win32k information");
            goto clean;
        }

        pShadowSSDT = GetSsdtShadowStructure(hDevice);
        if(pShadowSSDT == NULL)
        {
            DisplayErrorMsg("Couldn't retrieve SSDT shadow base address");
            goto clean;
        }

        pEthreadGui = GetGUIThread(hDevice);
        if(pEthreadGui == NULL)
        {
            DisplayErrorMsg("Couldn't retrieve a GUI-thread");
            goto clean;
        }
        
        printf(" INFO: ETHREAD GUI: 0x%x\n", pEthreadGui);
        
        pEprocessWithGuiThread = Ethread2Eprocess(hDevice, pEthreadGui);
        if(pEprocessWithGuiThread == NULL)
        {
            DisplayErrorMsg("Couldn't obtain eprocess pointer");
            goto clean;
        }

        pFunctShadowSSDT = (PDWORD)malloc(sizeof(DWORD) * pShadowSSDT->Limit);
        if(pFunctShadowSSDT == NULL)
        {
            DisplayAllocationFailureMsg();
            goto clean;
        }
        
        printf(" INFO: EPROCESS GUI: 0x%x\n", pEprocessWithGuiThread);

        read_kern_m.dst_address = pFunctShadowSSDT;
        read_kern_m.other_info = pEprocessWithGuiThread;
        read_kern_m.size = sizeof(DWORD) * pShadowSSDT->Limit;
        read_kern_m.src_address = pShadowSSDT->Base;
        read_kern_m.type = SYM_TYP_READWITHSTACKATTACH;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            DisplayIOCTLFailureMsg();
            goto clean;
        }

        pListHead = SsdtHookingDetection(hDevice, pShadowSSDT, pFunctShadowSSDT, (DWORD)pWin32kInfo->ImageBaseAddress, (DWORD)pWin32kInfo->ImageSize);
  
        clean:
        if(pShadowSSDT != NULL)
            free(pShadowSSDT);

        if(pWin32kInfo != NULL);
            free(pWin32kInfo);   

        if(pFunctShadowSSDT != NULL)
            free(pFunctShadowSSDT);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pListHead;
}

PSLIST_HEADER SsdtSystemHookingDetection(HANDLE hDevice)
{
    PSLIST_HEADER pListHead = NULL;
    PSYSTEM_MODULE pKernInfo = NULL;
    PKSERVICE_TABLE_DESCRIPTOR pSystemSSDT = NULL;
    PDWORD pFunctSystemSSDT = NULL;
    READ_KERN_MEM_t read_kern_m = {0};

    __try
    {
        pKernInfo = GetKernelModuleInformation();
        if(pKernInfo == NULL)
        {
            DisplayErrorMsg("Couldn't retrieve kernel information");
            goto clean;
        }

        pSystemSSDT = GetSsdtSystemStructure(hDevice);
        if(pSystemSSDT == NULL)
        {
            DisplayErrorMsg("Couldn't retrieve SSDT System base address");
            goto clean;
        }

        pFunctSystemSSDT = (PDWORD)malloc(sizeof(PDWORD) * pSystemSSDT->Limit);
        if(pFunctSystemSSDT == NULL)
        {
            DisplayAllocationFailureMsg();
            goto clean;
        }

        read_kern_m.dst_address = pFunctSystemSSDT;
        read_kern_m.size = sizeof(PDWORD) * pSystemSSDT->Limit;
        read_kern_m.src_address = pSystemSSDT->Base;
        read_kern_m.type = SYM_TYP_NULL;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            DisplayIOCTLFailureMsg();
            goto clean;
        }

        pListHead = SsdtHookingDetection(hDevice, pSystemSSDT, pFunctSystemSSDT, (DWORD)pKernInfo->ImageBaseAddress, (DWORD)pKernInfo->ImageSize);
        
        clean:
        if(pKernInfo != NULL)
            free(pKernInfo);

        if(pSystemSSDT != NULL)
            free(pSystemSSDT);

        if(pFunctSystemSSDT != NULL)
            free(pFunctSystemSSDT);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pListHead;
}

PSLIST_HEADER SsdtHookingDetection(HANDLE hDevice, PKSERVICE_TABLE_DESCRIPTOR pSsdt, PDWORD pFunctSsdt, DWORD modBase, DWORD modSize)
{
    PSLIST_HEADER pListHead = NULL;
    PSLIST_ENTRY pListEntry = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;
    DWORD i = 0, mobEnd = modBase + modSize;
    READ_KERN_MEM_t read_kern_mem = {0};

    __try
    {
        pListHead = (PSLIST_HEADER)malloc(sizeof(SLIST_HEADER));
        if(pListHead == NULL)
        {
            DisplayAllocationFailureMsg();
            return NULL;
        }
        
        InitializeSListHead(pListHead);

        for(; i < pSsdt->Limit; ++i)
        {
            if(pFunctSsdt[i] < modBase || pFunctSsdt[i] > mobEnd)
            {
                pHookInfo = malloc(sizeof(HOOK_INFORMATION));
                if(pHookInfo == NULL)
                {
                    DisplayAllocationFailureMsg();
                    
                    free(pListHead);
                    return NULL;
                }

                pHookInfo->functionHook = pFunctSsdt[i];
                pHookInfo->idSyscall = i;
                pHookInfo->nameOfHooker = IsAddressInADriver(pFunctSsdt[i]);
                PushHookInformationEntry(pListHead, pHookInfo);
            }
        }    
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pListHead;
}

VOID PushHookInformationEntry(PSLIST_HEADER pListHead, PHOOK_INFORMATION entry)
{
    InterlockedPushEntrySList(pListHead, &(entry->SListEntry));
}

PHOOK_INFORMATION PopHookInformationEntry(PSLIST_HEADER pListHead)
{
    PSLIST_ENTRY pListEntry = NULL;

    pListEntry = InterlockedPopEntrySList(pListHead);
    if(pListEntry == NULL)
        return NULL;
    
    return CONTAINING_RECORD(pListEntry, HOOK_INFORMATION, SListEntry);
}

PCHAR IsAddressInADriver(DWORD pFunct)
{
    PCHAR pDriverName = NULL;
    DWORD i = 0, imageBase = 0, imageEnd = 0, sizeStr = 0;
    PSYSTEM_MODULE_INFORMATION pSysModulesInfos = NULL;

    __try
    {
        pSysModulesInfos = GetModuleList();
        if(pSysModulesInfos == NULL)
        {
            DisplayErrorMsg("Modules list is equal to NULL");
            return NULL;
        }

        for(; i < pSysModulesInfos->ModulesCount; ++i)
        {
            imageBase = (imageEnd = (DWORD)pSysModulesInfos->Modules[i].ImageBaseAddress);
            imageEnd += pSysModulesInfos->Modules[i].ImageSize;

            if(pFunct >= imageBase && pFunct <= imageEnd)
            {
                sizeStr = strlen(pSysModulesInfos->Modules[i].Name) + 1;
                pDriverName = (PCHAR)malloc(sizeStr);
                if(pDriverName == NULL)
                {
                    DisplayAllocationFailureMsg();
                    return NULL;
                }

                memset(pDriverName, 0, sizeStr);
                memcpy(pDriverName, pSysModulesInfos->Modules[i].Name, sizeStr - 1);
                free(pSysModulesInfos);
                return pDriverName;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    free(pSysModulesInfos);
    return NULL;
}

PSYSTEM_MODULE GetKernelModuleInformation()
{
    PSYSTEM_MODULE_INFORMATION pSysModuleList = NULL;
    PSYSTEM_MODULE pSysModule = NULL;

    __try
    {
        pSysModuleList = GetModuleList();
        if(pSysModuleList == NULL)
        {
            DisplayErrorMsg("Modules list is equal to NULL");
            goto clean;
        }

        if(pSysModuleList->ModulesCount == 0)
        {
            DisplayErrorMsg("ModulesCount is equal to 0");
            goto clean;
        }

        pSysModule = (PSYSTEM_MODULE)malloc(sizeof(SYSTEM_MODULE));
        if(pSysModule == NULL)
        {
            DisplayAllocationFailureMsg();
            goto clean;
        }

        memcpy(pSysModule, pSysModuleList->Modules, sizeof(SYSTEM_MODULE));

        clean:

        if(pSysModuleList != NULL)
            free(pSysModuleList);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pSysModule;
}

PSYSTEM_MODULE GetWin32kModuleInformation()
{
    PSYSTEM_MODULE pSysModule = NULL;

    __try
    {
        pSysModule = GetModuleInformation("win32k.sys");
        if(pSysModule == NULL)
        {
            DisplayErrorMsg("Couldn't obtain your module information");
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pSysModule;
}

PSYSTEM_MODULE GetModuleInformation(PCHAR pModuleName)
{
    PSYSTEM_MODULE_INFORMATION pSysModuleList = NULL;
    PSYSTEM_MODULE pSysModule = NULL, pSysModuleFound = NULL;
    DWORD i = 0;

    __try
    {
        pSysModuleList = GetModuleList();
        if(pSysModuleList == NULL)
        {
            DisplayErrorMsg("Modules list is equal to NULL");
            goto clean;
        }

        for(;  i < pSysModuleList->ModulesCount; ++i)
        {
            if(strstr(pSysModuleList->Modules[i].Name, pModuleName) != NULL)
            {
                pSysModuleFound = &pSysModuleList->Modules[i];
                break;
            }
        }

        if(pSysModuleFound == NULL)
        {
            DisplayErrorMsg("Couldn't find your module");
            goto clean;
        }

        pSysModule = (PSYSTEM_MODULE)malloc(sizeof(SYSTEM_MODULE));
        if(pSysModule == NULL)
        {
            DisplayAllocationFailureMsg();
            goto clean;
        }

        memcpy(pSysModule, pSysModuleFound, sizeof(SYSTEM_MODULE));

        clean:

        if(pSysModuleList != NULL)
            free(pSysModuleList);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pSysModule;
}

PSYSTEM_MODULE_INFORMATION GetModuleList()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG neededSize = 0;
    PSYSTEM_MODULE_INFORMATION pModuleList = NULL;

    __try
    {
        ZwQuerySystemInformation(SystemModuleInformation,
            &neededSize,
            0,
            &neededSize
            );

        pModuleList = (PSYSTEM_MODULE_INFORMATION)malloc(neededSize);
        if(pModuleList == NULL)
            return pModuleList;

        status = ZwQuerySystemInformation(SystemModuleInformation,
            pModuleList,
            neededSize,
            0
            );

        if(!NT_SUCCESS(status))
        {
            DisplayErrorMsg("ZwQuerySystemInformation failed");
            free(pModuleList);
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pModuleList;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtSystemStructure(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtSystem = NULL;
    READ_KERN_MEM_t read_kern_mem = {0};
    
    pSsdtSystem = (PKSERVICE_TABLE_DESCRIPTOR)malloc(sizeof(KSERVICE_TABLE_DESCRIPTOR));
    if(pSsdtSystem == NULL)
    {
        DisplayAllocationFailureMsg();
        return NULL;
    }

    read_kern_mem.type = SYM_TYP_SSDT_SYSTEM;
    read_kern_mem.dst_address = pSsdtSystem;
    read_kern_mem.size = sizeof(KSERVICE_TABLE_DESCRIPTOR);
    
    if(IOCTLReadKernMem(hDevice, &read_kern_mem) == NULL)
    {
        DisplayIOCTLFailureMsg();
        free(pSsdtSystem);
        return NULL;
    }

    return pSsdtSystem;
}

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
            DisplayAllocationFailureMsg();
            return NULL;
        }

        state = ZwQuerySystemInformation(SystemProcessInformation , pProcessInfo , size , &size);
        if(!NT_SUCCESS(state))
        {
            DisplayErrorMsg("ZwQuerySystemInformation failed");
            free(pProcessInfo);
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pProcessInfo;
}

PDWORD GetGUIThread(HANDLE hDevice)
{
    PSYSTEM_PROCESS_INFORMATION pProcessInfos = NULL, pProcessInformation = NULL;
    PSYSTEM_THREAD pThread = NULL;
    NTSTATUS ntState = 0;
    DWORD i = 0;
    READ_KERN_MEM_t read_kern_m = {0};
    PDWORD pEprocess = NULL, pEthreadGuiThread = NULL, pEthread = NULL, pSsdtSystem = NULL, pWin32Thread = NULL;    

    __try
    {
        if(Offsets.isSupported == FALSE)
        {
            DisplayErrorMsg("This function requires offsets support");
            return NULL;
        }

        pProcessInfos = GetProcessList();
        if(pProcessInfos == NULL)
        {
            DisplayErrorMsg("GetProcessList failed");
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
                        DisplayErrorMsg("GetETHREADStructureByTid failed");
                        free(pProcessInformation);
                        return NULL;
                    }
                                        
                    read_kern_m.dst_address = &pWin32Thread;
                    read_kern_m.src_address = (PVOID)((DWORD)pEthread + Offsets.KTHREADWin32Thread);
                    read_kern_m.size = sizeof(DWORD);
                    read_kern_m.type = SYM_TYP_NULL;

                    if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
                    {
                        free(pProcessInformation);
                        DisplayIOCTLFailureMsg();
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
        _EXCEPT_();

    return pEthreadGuiThread;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtShadowStructure(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtShadow = NULL, pSsdtShadowAddr = NULL;
    PDWORD pGuiEthread = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    
    __try
    {
        /* 
           Technic : 
            -> Find a GUI-thread
            -> ETHREAD.KTHREAD.ServiceTable will point on KeServiceDescriptorShadowTable
        */
        pGuiEthread = GetGUIThread(hDevice);
        if(pGuiEthread == NULL)
        {
            DisplayErrorMsg("GetGUIThread failed");
            return NULL;
        }

        read_kern_m.dst_address = &pSsdtShadowAddr;
        read_kern_m.src_address = (PVOID)((DWORD)pGuiEthread + Offsets.KTHREADServiceTable);
        read_kern_m.size = sizeof(DWORD);
        read_kern_m.type = SYM_TYP_NULL;
        
        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            DisplayIOCTLFailureMsg();
            return NULL;
        }

        pSsdtShadowAddr++;
        pSsdtShadow = (PKSERVICE_TABLE_DESCRIPTOR)malloc(sizeof(KSERVICE_TABLE_DESCRIPTOR));
        if(pSsdtShadow == NULL)
        {
            DisplayAllocationFailureMsg();
            return NULL;
        }

        read_kern_m.dst_address = pSsdtShadow;
        read_kern_m.src_address = pSsdtShadowAddr;
        read_kern_m.size = sizeof(KSERVICE_TABLE_DESCRIPTOR);
        read_kern_m.type = SYM_TYP_NULL;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            DisplayIOCTLFailureMsg();
            free(pSsdtShadow);
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();
    
    return pSsdtShadow;
}

PDWORD GetETHREADStructureByTid(HANDLE hDevice, DWORD threadID)
{
    PDWORD pEthread = NULL;
    READ_KERN_MEM_t read_kern_mem = {0};

    read_kern_mem.type = SYM_TYP_PSLOUTHBYID;
    read_kern_mem.src_address = (PVOID)threadID;
    read_kern_mem.dst_address = &pEthread;
    read_kern_mem.size = sizeof(PDWORD);

    if(IOCTLReadKernMem(hDevice, &read_kern_mem) == NULL)
    {
        DisplayIOCTLFailureMsg();
        return NULL;
    }

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
            DisplayErrorMsg("This function requires offset support");
            return NULL;
        }

        read_kern_m.dst_address = &pEprocess;
        read_kern_m.size = sizeof(PDWORD);
        read_kern_m.src_address = (PVOID)((DWORD)pEthread + Offsets.ETHREAD2Eprocess);
        read_kern_m.type = SYM_TYP_NULL;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            DisplayIOCTLFailureMsg();
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        _EXCEPT_();

    return pEprocess;
}