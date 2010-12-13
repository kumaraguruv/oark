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
#include "modules.h"
#include "process.h"
#include "list.h"
#include "pe.h"

#include <stdlib.h>
#include <string.h>

VOID CheckSSDTHooking(HANDLE hDevice)
{
    PHOOK_INFORMATION pHookInfo = NULL;
    PSLIST_HEADER pListHead = NULL;

    printf(" INFO: SSDT System Hook Information (0x%.8x):\n", GetSsdtSystemBaseAddress());
    printf(" INFO: SSDT Shadow Hook Information (0x%.8x):\n", GetSsdtShadowBaseAddress());
    /*
    pListHead = SsdtSystemHookingDetection(hDevice);
    if(pListHead == NULL)
    {
        OARK_ERROR("The list is empty");
        return;
    }

    printf(" INFO: SSDT System Hook Information (0x%.8x):\n", GetSsdtSystemBaseAddress(hDevice));

    while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
    {
        printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n Hooker driver: %s", pHookInfo->id, pHookInfo->addr, pHookInfo->name);
        if(pHookInfo->name != NULL)
            free(pHookInfo->name);
        free(pHookInfo);
    }
    printf("\n\n");
    free(pListHead);

    pListHead = SsdtShadowHookingDetection(hDevice);
    if(pListHead == NULL)
    {
        OARK_ERROR("The list is empty");
        return;
    }

    printf(" INFO: SSDT Shadow Hook Information (0x%.8x):\n", GetSsdtShadowBaseAddress(hDevice));
    while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
    {
        printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n Hooker driver: %s", pHookInfo->id, pHookInfo->addr, pHookInfo->name);
        if(pHookInfo->name != NULL)
            free(pHookInfo->name);
        free(pHookInfo);
    }
    printf("\n\n");
    free(pListHead);

    pListHead = CheckXraynPoc(hDevice);
    printf(" INFO: Xrayn PoC Hook Information:\n");
    while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
    {
        printf(" \n----\n Process Id: 0x%.4x\n ServiceTable: 0x%.8x in '%s'\n", pHookInfo->id, pHookInfo->addr, pHookInfo->name);
        if(pHookInfo->name != NULL)
            free(pHookInfo->name);
        free(pHookInfo);
    }
    printf("\n\n");
    free(pListHead);
    */
}

PSLIST_HEADER CheckXraynPoc(HANDLE hDevice)
{
    PSYSTEM_PROCESS_INFORMATION pProcessInfos = NULL, pProcessInformation = NULL;
    PKSERVICE_TABLE_DESCRIPTOR pSsdtSystem = NULL, pSsdtShadow = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    PSYSTEM_THREAD pThread = NULL;
    PSLIST_HEADER pListHead = NULL;
    NTSTATUS ntState = 0;
    PDWORD pEthread = NULL, pServiceTable = NULL;    
    DWORD i = 0;

    __try
    {
        printf(" INFO: Checking Xrayn PoC\n");
        if(Offsets.isSupported == FALSE)
        {
            OARK_ERROR("This function requires offsets support");
            goto clean;
        }

        pSsdtShadow = (PKSERVICE_TABLE_DESCRIPTOR)GetSsdtShadowBaseAddress(hDevice);
        pSsdtSystem = GetSsdtSystemBaseAddress(hDevice);

        if(pSsdtSystem == NULL || pSsdtShadow == NULL)
        {
            OARK_ERROR("GetSsdt[Shadow|System]BaseAddress failed");
            goto clean;
        }

        pProcessInfos = GetProcessList();
        if(pProcessInfos == NULL)
        {
            OARK_ERROR("GetProcessList failed");
            goto clean;
        }

        pListHead = (PSLIST_HEADER)malloc(sizeof(SLIST_HEADER));
        if(pListHead == NULL)
        {
            OARK_ALLOCATION_ERROR();
            goto clean;
        }

        pProcessInformation = pProcessInfos;
        InitializeSListHead(pListHead);

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
                        CleanHookInfoList(pListHead);
                        free(pListHead);
                        goto clean;
                    }

                    read_kern_m.dst_address = &pServiceTable;
                    read_kern_m.src_address = (PVOID)((DWORD)pEthread + Offsets.KTHREADServiceTable);
                    read_kern_m.size = sizeof(DWORD);
                    read_kern_m.type = SYM_TYP_NULL;

                    if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
                    {
                        OARK_IOCTL_ERROR();
                        CleanHookInfoList(pListHead);
                        free(pListHead);
                        goto clean;
                    }
                    
                    if(pServiceTable != (PDWORD)pSsdtSystem && pServiceTable != (PDWORD)pSsdtShadow)
                    {
                        pHookInfo = (PHOOK_INFORMATION)malloc(sizeof(HOOK_INFORMATION));
                        if(pHookInfo == NULL)
                        {
                            CleanHookInfoList(pListHead);
                            free(pListHead);
                            pListHead = NULL;
                            goto clean;
                        }

                        ZeroMemory(pHookInfo, sizeof(HOOK_INFORMATION));
                        pHookInfo->addr = (DWORD)pServiceTable;
                        pHookInfo->id = (DWORD)pProcessInfos->ProcessId;
                        PushHookInformationEntry(pListHead, pHookInfo);
                        break;
                    }
                }
            }

            pProcessInfos = (PSYSTEM_PROCESS_INFORMATION)((((DWORD)pProcessInfos) + pProcessInfos->NextEntryOffset));
        }

        clean:
        if(pProcessInformation != NULL)
            free(pProcessInformation);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pListHead;
}

PSLIST_HEADER SsdtShadowHookingDetection(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pShadowSSDT = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    PSYSTEM_MODULE pWin32kInfo = NULL;
    PSLIST_HEADER pListHead = NULL;
    PDWORD pEprocessWithGuiThread = NULL, pEthreadGui = NULL, pFunctShadowSSDT = NULL;
    
    __try
    {
        pWin32kInfo = GetWin32kModuleInformation();
        if(pWin32kInfo == NULL)
        {
            OARK_ERROR("Couldn't retrieve win32k information");
            goto clean;
        }

        pShadowSSDT = GetSsdtShadowStructure(hDevice);
        if(pShadowSSDT == NULL)
        {
            OARK_ERROR("Couldn't retrieve SSDT shadow base address");
            goto clean;
        }

        pEthreadGui = GetGUIThread(hDevice);
        if(pEthreadGui == NULL)
        {
            OARK_ERROR("Couldn't retrieve a GUI-thread");
            goto clean;
        }
        
        printf(" INFO: ETHREAD GUI: 0x%x\n", pEthreadGui);
        
        pEprocessWithGuiThread = Ethread2Eprocess(hDevice, pEthreadGui);
        if(pEprocessWithGuiThread == NULL)
        {
            OARK_ERROR("Couldn't obtain eprocess pointer");
            goto clean;
        }

        pFunctShadowSSDT = (PDWORD)malloc(sizeof(DWORD) * pShadowSSDT->Limit);
        if(pFunctShadowSSDT == NULL)
        {
            OARK_IOCTL_ERROR();
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
            OARK_IOCTL_ERROR();
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
        OARK_EXCEPTION();

    return pListHead;
}

PSLIST_HEADER SsdtSystemHookingDetection(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSystemSSDT = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    PSYSTEM_MODULE pKernInfo = NULL;
    PSLIST_HEADER pListHead = NULL;   
    PDWORD pFunctSystemSSDT = NULL;

    __try
    {
        pKernInfo = GetKernelModuleInformation();
        if(pKernInfo == NULL)
        {
            OARK_ERROR("Couldn't retrieve kernel information");
            goto clean;
        }

        pSystemSSDT = GetSsdtSystemStructure(hDevice);
        if(pSystemSSDT == NULL)
        {
            OARK_ERROR("Couldn't retrieve SSDT System base address");
            goto clean;
        }

        pFunctSystemSSDT = (PDWORD)malloc(sizeof(PDWORD) * pSystemSSDT->Limit);
        if(pFunctSystemSSDT == NULL)
        {
            OARK_IOCTL_ERROR();
            goto clean;
        }

        read_kern_m.dst_address = pFunctSystemSSDT;
        read_kern_m.size = sizeof(PDWORD) * pSystemSSDT->Limit;
        read_kern_m.src_address = pSystemSSDT->Base;
        read_kern_m.type = SYM_TYP_NULL;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            OARK_IOCTL_ERROR();
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
        OARK_EXCEPTION();

    return pListHead;
}

PSLIST_HEADER SsdtHookingDetection(HANDLE hDevice, PKSERVICE_TABLE_DESCRIPTOR pSsdt, PDWORD pFunctSsdt, DWORD modBase, DWORD modSize)
{
    PHOOK_INFORMATION pHookInfo = NULL;
    READ_KERN_MEM_t read_kern_mem = {0};
    PSLIST_HEADER pListHead = NULL;
    PSLIST_ENTRY pListEntry = NULL;
    DWORD i = 0, mobEnd = modBase + modSize;

    __try
    {
        pListHead = (PSLIST_HEADER)malloc(sizeof(SLIST_HEADER));
        if(pListHead == NULL)
        {
            OARK_IOCTL_ERROR();
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
                    OARK_IOCTL_ERROR();
                    
                    CleanHookInfoList(pListHead);
                    free(pListHead);
                    return NULL;
                }

                pHookInfo->addr = pFunctSsdt[i];
                pHookInfo->id = i;
                pHookInfo->name = IsAddressInADriver(pFunctSsdt[i]);
                PushHookInformationEntry(pListHead, pHookInfo);
            }
        }    
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pListHead;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtSystemStructure(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtSystem = NULL, pSsdtSystemBaseAddress = NULL;
    READ_KERN_MEM_t read_kern_mem = {0};
    
    __try
    {
        pSsdtSystem = (PKSERVICE_TABLE_DESCRIPTOR)malloc(sizeof(KSERVICE_TABLE_DESCRIPTOR));
        if(pSsdtSystem == NULL)
        {
            OARK_IOCTL_ERROR();
            return NULL;
        }
        
        pSsdtSystemBaseAddress = GetSsdtSystemBaseAddress(hDevice);
        if(pSsdtSystemBaseAddress == NULL)
        {
            OARK_ERROR("GetSsdtSystemBaseAddress failed");
            return NULL;
        }

        read_kern_mem.type = SYM_TYP_NULL;
        read_kern_mem.src_address = pSsdtSystemBaseAddress;
        read_kern_mem.dst_address = pSsdtSystem;
        read_kern_mem.size = sizeof(KSERVICE_TABLE_DESCRIPTOR);

        if(IOCTLReadKernMem(hDevice, &read_kern_mem) == NULL)
        {
            OARK_IOCTL_ERROR();
            free(pSsdtSystem);
            pSsdtSystem = NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSsdtSystem;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtShadowStructure(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtShadow = NULL, pSsdtShadowAddr = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    
    __try
    {
        
        pSsdtShadowAddr = GetSsdtShadowBaseAddress(hDevice);
        if(pSsdtShadowAddr == NULL)
        {
            OARK_ERROR("GetSsdtShadowBaseAddress failed");
            return NULL;
        }

        pSsdtShadowAddr++;
        pSsdtShadow = (PKSERVICE_TABLE_DESCRIPTOR)malloc(sizeof(KSERVICE_TABLE_DESCRIPTOR));
        if(pSsdtShadow == NULL)
        {
            OARK_IOCTL_ERROR();
            return NULL;
        }

        read_kern_m.dst_address = pSsdtShadow;
        read_kern_m.src_address = pSsdtShadowAddr;
        read_kern_m.size = sizeof(KSERVICE_TABLE_DESCRIPTOR);
        read_kern_m.type = SYM_TYP_NULL;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
        {
            OARK_IOCTL_ERROR();
            free(pSsdtShadow);
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
    
    return pSsdtShadow;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtSystemBaseAddress()
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtSystem = NULL;
    PSYSTEM_MODULE pKernInfo = NULL;
    HMODULE pKern = NULL;
    PCHAR pNameExport = NULL;
    DWORD i = 0;

    __try
    {
        pKern = LoadKernInAddrSpace();
        if(pKern == NULL)
        {
            OARK_ERROR("LoadKernInAddrSpace failed");
            goto clean;
        }
        
        pKernInfo = GetKernelModuleInformation();
        if(pKernInfo == NULL)
        {
            OARK_ERROR("GetKernelModuleInformation failed");
            goto clean;
        }

        pSsdtSystem = (PKSERVICE_TABLE_DESCRIPTOR)GetExportedSymbol(pKern, "KeServiceDescriptorTable");
        if(pSsdtSystem == NULL)
            goto clean;

        (DWORD)pSsdtSystem += (DWORD)pKernInfo->ImageBaseAddress;

        clean:
        if(pKern != NULL)
            FreeLibrary(pKern);

        if(pKernInfo != NULL)
            free(pKernInfo);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSsdtSystem;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtShadowBaseAddress()
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtShadow = NULL;
    PSYSTEM_MODULE pKernInfo = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    HANDLE pKern = NULL;
    PDWORD pGuiEthread = NULL;
    PUCHAR pKeAddSystemServTab = NULL;
    DWORD i = 0;

    __try
    {

        pKern = LoadKernInAddrSpace();
        if(pKern == NULL)
        {
            OARK_ERROR("LoadKernInAddrSpace failed");
            goto clean;
        }

        pKernInfo = GetKernelModuleInformation();
        if(pKernInfo == NULL)
        {
            OARK_ERROR("GetWin32kModuleInformation failed");
            goto clean;
        }

        pKeAddSystemServTab = (PUCHAR)GetExportedSymbol(pKern, "KeAddSystemServiceTable");
        if(pKeAddSystemServTab == NULL)
        {
            OARK_ERROR("GetExportedSymbol failed");
            goto clean;
        }

        pKeAddSystemServTab += (DWORD)pKern;

        for(; i < 100; ++i)
        {
            /*
                lkd> u KeAddSystemServiceTable l 40
                nt!KeAddSystemServiceTable:
                805ba589 8bff             mov     edi,edi
                805ba58b 55               push     ebp
                805ba58c 8bec             mov     ebp,esp
                805ba58e 837d1803         cmp     dword ptr [ebp+18h],3
                805ba592 774e             ja       nt!KeAddSystemServiceTable+0x6b (805ba5e2)
                805ba594 8b4518           mov     eax,dword ptr [ebp+18h]
                805ba597 c1e004           shl     eax,4
                805ba59a 83b880a6558000   cmp     dword ptr nt!KeServiceDescriptorTable (8055a680)[eax],0
                805ba5a1 753f             jne     nt!KeAddSystemServiceTable+0x6b (805ba5e2)
                805ba5a3 8d8840a65580     lea     ecx,nt!KeServiceDescriptorTableShadow (8055a640)[eax]
            */
            printf("0x%x, ", pKeAddSystemServTab[i]);
            if(i % 2 == 0)
                printf("\n");

            if(pKeAddSystemServTab[i] == 0x8d && pKeAddSystemServTab[i+1] == 0x88)
            {
                printf("Kern loaded @0x%x, KeAddSystemServTab @0x%x\n", pKern, pKeAddSystemServTab);
                pSsdtShadow = (PKSERVICE_TABLE_DESCRIPTOR)*(PDWORD)(pKeAddSystemServTab+2);
                //(DWORD)pSsdtShadow -= (DWORD)pKern;
                //(DWORD)pSsdtShadow += (DWORD)pKernInfo->ImageBaseAddress;
                break;
            }
        }

        clean:
        if(pKernInfo != NULL)
            free(pKernInfo);

        if(pKern != NULL)
            FreeLibrary(pKern);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSsdtShadow;
}