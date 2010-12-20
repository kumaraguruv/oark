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
#include "unicode.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

VOID CheckSSDTHooking(HANDLE hDevice)
{
    PHOOK_INFORMATION pHookInfo = NULL;
    PSLIST_HEADER pListHead = NULL;
    PCHAR* pTable = NULL;
    DWORD nbEntry = 0;
    BOOL ret = FALSE;

    __try
    {       
        pListHead = SsdtSystemHookingDetection(hDevice, &nbEntry);
        pTable = (PCHAR*)malloc(sizeof(PCHAR) * nbEntry);
        if(pTable == NULL)
        {
            OARK_ALLOCATION_ERROR();

            CleanHookInfoList(pListHead);
            free(pListHead);
            return;
        }
        memset(pTable, 0, sizeof(PCHAR) * nbEntry);

        ret = BuildSystemApiNameTable(pTable, nbEntry);
        if(ret == FALSE)
        {
            OARK_ERROR("BuildNativeApiNameTable failed");
            
            CleanHookInfoList(pListHead);
            free(pTable);
            free(pListHead);
            return;
        }
        
        printf(" INFO: SSDT System Hook Information (0x%.8x):\n", GetSsdtSystemBaseAddress(hDevice));
        while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
        {
            printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n API Name: %s\n Hooker driver: %s", pHookInfo->id, pHookInfo->addr, pTable[pHookInfo->id], pHookInfo->name);
            if(pHookInfo->name != NULL)
                free(pHookInfo->name);
            free(pHookInfo);
        }
        printf("\n\n");
        free(pListHead);
        free(pTable);

        pListHead = SsdtShadowHookingDetection(hDevice, NULL);

        printf(" INFO: SSDT Shadow Hook Information (0x%.8x):\n", GetSsdtShadowBaseAddress(hDevice));
        while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
        {
            printf(" \n----\n Syscall ID: 0x%.4x\n Function address: 0x%.8x\n API Name: %s\n Hooker driver: %s", pHookInfo->id, pHookInfo->addr, Offsets.pGuiSyscallName[pHookInfo->id], pHookInfo->name);
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
            printf(" \n----\n Process Id: 0x%.4x - %s (TID: 0x%.3x)\n ETHREAD Pointer: 0x%.8x\n ServiceTable: 0x%.8x\n", pHookInfo->id, pHookInfo->name, pHookInfo->other[1], pHookInfo->other[0], pHookInfo->addr);
            if(pHookInfo->name != NULL)
                free(pHookInfo->name);
            free(pHookInfo);
        }
        printf("\n\n");
        free(pListHead);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

PSLIST_HEADER CheckXraynPoc(HANDLE hDevice)
{
    PSYSTEM_PROCESS_INFORMATION pProcessInfos = NULL, pProcessInformation = NULL;
    PKSERVICE_TABLE_DESCRIPTOR pSsdtSystem = NULL, pSsdtShadow = NULL;
    PHOOK_INFORMATION pHookInfo = NULL;
    READ_KERN_MEM_t read_kern_m = {0};
    PSLIST_HEADER pListHead = NULL;
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

        pSsdtShadow = GetSsdtShadowBaseAddress(hDevice);
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
                        continue;

                    read_kern_m.dst_address = &pServiceTable;
                    read_kern_m.src_address = (PVOID)((DWORD)pEthread + Offsets.KTHREADServiceTable);
                    read_kern_m.size = sizeof(DWORD);
                    read_kern_m.type = SYM_TYP_NULL;

                    if(IOCTLReadKernMem(hDevice, &read_kern_m) == NULL)
                    {
                        OARK_IOCTL_ERROR();
                        CleanHookInfoList(pListHead);
                        free(pListHead);
                        pListHead = NULL;
                        goto clean;
                    }

                    if(pServiceTable != (PDWORD)pSsdtSystem && pServiceTable != (PDWORD)pSsdtShadow)
                    {
                        pHookInfo = (PHOOK_INFORMATION)malloc(sizeof(HOOK_INFORMATION));
                        if(pHookInfo == NULL)
                        {
                            OARK_ALLOCATION_ERROR();
                            CleanHookInfoList(pListHead);
                            free(pListHead);
                            pListHead = NULL;
                            goto clean;
                        }

                        ZeroMemory(pHookInfo, sizeof(HOOK_INFORMATION));
                        pHookInfo->addr = (DWORD)pServiceTable;
                        pHookInfo->id = (DWORD)pProcessInfos->ProcessId;
                        pHookInfo->name = UnicodeToAnsi(pProcessInfos->ImageName.Buffer);
                        pHookInfo->other[0] = (PVOID)pEthread;
                        pHookInfo->other[1] = (PVOID)pProcessInfos->Threads[i].ClientId.UniqueThread;
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

PSLIST_HEADER SsdtShadowHookingDetection(HANDLE hDevice, PDWORD nbEntry)
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

        pListHead = SsdtHookingDetection(pShadowSSDT, pFunctShadowSSDT, (DWORD)pWin32kInfo->ImageBaseAddress, (DWORD)pWin32kInfo->ImageSize, nbEntry);
  
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

PSLIST_HEADER SsdtSystemHookingDetection(HANDLE hDevice, PDWORD nbEntry)
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

        pListHead = SsdtHookingDetection(pSystemSSDT, pFunctSystemSSDT, (DWORD)pKernInfo->ImageBaseAddress, (DWORD)pKernInfo->ImageSize, nbEntry);
        
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

PSLIST_HEADER SsdtHookingDetection(PKSERVICE_TABLE_DESCRIPTOR pSsdt, PDWORD pFunctSsdt, DWORD modBase, DWORD modSize, PDWORD nbEntry)
{
    PHOOK_INFORMATION pHookInfo = NULL;
    PSLIST_HEADER pListHead = NULL;
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
        if(nbEntry != NULL)
            *nbEntry = pSsdt->Limit;

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
            OARK_ALLOCATION_ERROR();
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
            OARK_ALLOCATION_ERROR();
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

        pSsdtSystem = (PKSERVICE_TABLE_DESCRIPTOR)GetExportedSymbol(pKern, "KeServiceDescriptorTable", FALSE);
        if(pSsdtSystem == NULL)
        {
            OARK_ERROR("GetExportedSymbol failed");
            goto clean;
        }

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
    PUCHAR pKeAddSystemServTab = NULL;
    DWORD i = 0, imgBaseKern = 0;

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

        pKeAddSystemServTab = (PUCHAR)GetExportedSymbol(pKern, "KeAddSystemServiceTable", TRUE);
        if(pKeAddSystemServTab == NULL)
        {
            OARK_ERROR("GetExportedSymbol failed");
            goto clean;
        }

        imgBaseKern = (DWORD)GetPEField(pKern, IMAGE_BASE);

        for(; i < 100; ++i)
        {
            /*
                kd> u nt!KeAddSystemServiceTable l 40
                nt!KeAddSystemServiceTable:
                80595542 8bff            mov     edi,edi
                80595544 55              push    ebp
                80595545 8bec            mov     ebp,esp
                80595547 837d1803        cmp     dword ptr [ebp+18h],3
                8059554b 7760            ja      nt!KeAddSystemServiceTable+0x6b (805955ad)
                8059554d 8b4518          mov     eax,dword ptr [ebp+18h]
                80595550 c1e004          shl     eax,4
                80595553 83b88021558000  cmp     dword ptr nt!KeServiceDescriptorTable (80552180)[eax],0
                8059555a 7551            jne     nt!KeAddSystemServiceTable+0x6b (805955ad)
                8059555c 8d8840215580    lea     ecx,nt!KeServiceDescriptorTableShadow (80552140)[eax]
            */

            if(pKeAddSystemServTab[i] == 0x8d && pKeAddSystemServTab[i+1] == 0x88)
            {
                pSsdtShadow = (PKSERVICE_TABLE_DESCRIPTOR)*(PDWORD)(pKeAddSystemServTab+i+2);
                
                //Get offset relative to imgBase
                (DWORD)pSsdtShadow -= (DWORD)pKern;
                
                //Remove reloc
                (INT)pSsdtShadow -= ((INT)imgBaseKern - (INT)pKern);

                //Final addr
                (DWORD)pSsdtShadow += (DWORD)pKernInfo->ImageBaseAddress;
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

BOOL BuildSystemApiNameTable(PCHAR* pTable, DWORD nb)
{
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = NULL;
    PIMAGE_DOS_HEADER pImgDosHead = NULL;
    HMODULE pNtdll = NULL;
    PDWORD pAddrExportFunct, pExportNames = NULL;
    PSHORT pAddrNamesOrd = NULL;
    PUCHAR pAddrExportedSym = NULL;
    PCHAR pNameExport = NULL;
    DWORD i = 0, j = 0, id = 0;
   
    __try
    {
        pNtdll = GetModuleHandleA("ntdll.dll");
        if(pNtdll == NULL)
        {
            OARK_ERROR("GetModuleHandleA failed");
            return FALSE;
        }

        pImgExportDir = GetExportTableDirectory(pNtdll);
        pImgDosHead = GetDosHeader(pNtdll);

        pExportNames = (PDWORD)((DWORD)pImgDosHead + pImgExportDir->AddressOfNames);
        pAddrExportFunct = (PDWORD)((DWORD)pImgDosHead + pImgExportDir->AddressOfFunctions);
        pAddrNamesOrd = (PSHORT)((DWORD)pImgDosHead + pImgExportDir->AddressOfNameOrdinals);
        
        for(; i < pImgExportDir->NumberOfFunctions && j < nb; ++i)
        {
            pNameExport = (PCHAR)((DWORD)pImgDosHead + pExportNames[i]);
            pAddrExportedSym = (PUCHAR)((DWORD)pImgDosHead + pAddrExportFunct[pAddrNamesOrd[i]]);
        
            if(*pAddrExportedSym == 0xB8 && 
               *(pAddrExportedSym+5) == 0xBA &&
               *(PDWORD)(pAddrExportedSym+6) == 0x7FFE0300)
            {
                id = *(PDWORD)(pAddrExportedSym+1);
                pTable[id] = pNameExport;
                ++j;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
    
    return TRUE;
}