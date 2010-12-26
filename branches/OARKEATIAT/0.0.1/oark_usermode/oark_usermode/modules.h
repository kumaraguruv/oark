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
 * @file   modules.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Modules stuff.
 *
 */

#ifndef _MODULES_H_
#define _MODULES_H_

#include "others.h"

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
 * @name    isAddressInKernel
 * @brief   This routine returns the answer to the question 'ptr is in kernel code ?'.
 *
 * This API is useful to know if an address is situated in kernel module.
 *
 * @param [in] pFunct  Address of the function.
 *
 * @retval TRUE  Address points into kernel module.
 * @retval FALSE  Address does not point into kernel module.
 *
 * Example Usage:
 * @code
 *    IsAddressInKernel(0x1337);
 * @endcode
 */
BOOL IsAddressInKernel(DWORD pFunc);

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
 * @name    LoadKernInAddrSpace
 * @brief   This routine loads kernel in virtual-address-space of caller.
 *
 * This API loads kernel image in process context.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to the binary in memory.
 *
 * Example Usage:
 * @code
 *    LoadKernInAddrSpace(); // Never forgotten to FreeLibrary the pointer !
 * @endcode
 */
HANDLE LoadKernInAddrSpace();

#endif