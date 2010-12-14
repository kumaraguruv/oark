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
 * @file   modules.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Modules stuff.
 *
 */
#include "modules.h"

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
            OARK_ERROR("Modules list is equal to NULL");
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
                    OARK_IOCTL_ERROR();
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
        OARK_EXCEPTION();

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
            OARK_ERROR("Modules list is equal to NULL");
            goto clean;
        }

        if(pSysModuleList->ModulesCount == 0)
        {
            OARK_ERROR("ModulesCount is equal to 0");
            goto clean;
        }

        pSysModule = (PSYSTEM_MODULE)malloc(sizeof(SYSTEM_MODULE));
        if(pSysModule == NULL)
        {
            OARK_IOCTL_ERROR();
            goto clean;
        }

        memcpy(pSysModule, pSysModuleList->Modules, sizeof(SYSTEM_MODULE));

        clean:

        if(pSysModuleList != NULL)
            free(pSysModuleList);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

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
            OARK_ERROR("Couldn't obtain your module information");
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

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
            OARK_ERROR("Modules list is equal to NULL");
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
            OARK_ERROR("Couldn't find your module");
            goto clean;
        }

        pSysModule = (PSYSTEM_MODULE)malloc(sizeof(SYSTEM_MODULE));
        if(pSysModule == NULL)
        {
            OARK_IOCTL_ERROR();
            goto clean;
        }

        memcpy(pSysModule, pSysModuleFound, sizeof(SYSTEM_MODULE));

        clean:

        if(pSysModuleList != NULL)
            free(pSysModuleList);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

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
            OARK_ERROR("ZwQuerySystemInformation failed");
            free(pModuleList);
            return NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pModuleList;
}