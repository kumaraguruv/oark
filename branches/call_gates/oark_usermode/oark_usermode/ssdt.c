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

#include <stdlib.h>
#include <string.h>

VOID CheckSSDTHooking(HANDLE hDevice)
{
    PSLIST_HEADER pListHead = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;

    pListHead = SsdtSystemHookingDetection(hDevice);
    if(pListHead == NULL)
    {
        OARK_ERROR("The list is empty");
        return;
    }

    printf(" INFO: SSDT System Hook Information (0x%.8x):\n", GetSsdtSystemBaseAddress(hDevice));

    while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
    {
        printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n Hooker driver: %s", pHookInfo->idSyscall, pHookInfo->functionHook, pHookInfo->nameOfHooker);
        if(pHookInfo->nameOfHooker != NULL)
            free(pHookInfo->nameOfHooker);
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
        OARK_EXCEPTION();

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

PKSERVICE_TABLE_DESCRIPTOR GetSsdtSystemBaseAddress(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtSystem = NULL;
    READ_KERN_MEM_t read_kern_m = {0};

    __try
    {
        read_kern_m.dst_address = &pSsdtSystem;
        read_kern_m.size = sizeof(PKSERVICE_TABLE_DESCRIPTOR);
        read_kern_m.type = SYM_TYP_SSDT_SYSTEM;

        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
            OARK_IOCTL_ERROR();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSsdtSystem;
}

PKSERVICE_TABLE_DESCRIPTOR GetSsdtShadowBaseAddress(HANDLE hDevice)
{
    PKSERVICE_TABLE_DESCRIPTOR pSsdtShadow = NULL;
    PDWORD pGuiEthread = NULL;
    READ_KERN_MEM_t read_kern_m = {0};

    __try
    {
        /* 
           Technic : 
            -> Find a GUI-thread
            -> ETHREAD.KTHREAD.ServiceTable will point on KeServiceDescriptorShadowTable
        */

        if(Offsets.isSupported == FALSE)
        {
            OARK_ERROR("This function needs offset support");
            return NULL;
        }

        pGuiEthread = GetGUIThread(hDevice);
        if(pGuiEthread == NULL)
        {
            OARK_ERROR("GetGUIThread failed");
            return NULL;
        }

        read_kern_m.dst_address = &pSsdtShadow;
        read_kern_m.src_address = (PVOID)((DWORD)pGuiEthread + Offsets.KTHREADServiceTable);
        read_kern_m.size = sizeof(DWORD);
        read_kern_m.type = SYM_TYP_NULL;
        
        if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
            OARK_IOCTL_ERROR();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSsdtShadow;
}