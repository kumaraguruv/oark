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

#pragma pack(1)
typedef struct
{
    PULONG Base;
    PULONG Count;
    ULONG Limit;
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
#pragma pack()

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
 * @name    CheckXraynPoc
 * @brief   Check Xrayn PoC.
 *
 * This API searchs and displays potential hook in KTHREAD.ServiceTable field.
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 *
 * @retval NULL An error occured.
 *         other A pointer to a SLIST_HEADER.
 *
 * Example Usage:
 * @code
 *    CheckXraynPoc(hDevice);
 * @endcode
 */
PSLIST_HEADER CheckXraynPoc(HANDLE hDevice);

/**
 * @name    GetSsdtSystemBaseAddress
 * @brief   Retrieves SSDT System base address.
 *
 * This API gives the SSDT System base address.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a KSERVICE_TABLE_DESCRIPTOR structure.
 *
 * Example Usage:
 * @code
 *    GetSsdtSystemBaseAddress();
 * @endcode
 */
PKSERVICE_TABLE_DESCRIPTOR GetSsdtSystemBaseAddress();

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
 * @name    GetSsdtShadowBaseAddress
 * @brief   Retrieves SSDT Shadow base address.
 *
 * This API gives the SSDT Shadow base address.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a KSERVICE_TABLE_DESCRIPTOR structure.
 *
 * Example Usage:
 * @code
 *    GetSsdtShadowBaseAddress(hDevice);
 * @endcode
 */
PKSERVICE_TABLE_DESCRIPTOR GetSsdtShadowBaseAddress();

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
 * @param [out] nbEntry Number of entries in SSDT.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to SLIST_HEADER structure, the head of the single linked list.
 *
 * Example Usage:
 * @code
 *    SsdtSystemHookingDetection(hDevice, &entry); 
 *    // /!\ Never forgotten to clean the list with PopInformationHookList and free for the 'name' field.
 * @endcode
 */
PSLIST_HEADER SsdtSystemHookingDetection(HANDLE hDevice, PDWORD nbEntry);

/**
 * @name    SsdtShadowHookingDetection
 * @brief   This routine returns information about hooked SSDT Shadow entries.
 *
 * This API gives informations relative to hooked SSDT Shadow entries.
 * NB : To manipulate SLIST_ENTRY use PopHookInformationList/PushHookInformationList
 *
 * @param [in] hDevice Handle of the OARK kernelmode driver.
 * @param [out] nbEntry Number of entries in SSDT.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to SLIST_HEADER structure, the head of the single linked list.
 *
 * Example Usage:
 * @code
 *    SsdtShadowHookingDetection(hDevice, NULL); 
 *    // /!\ Never forgotten to clean the list with PopInformationHookList and free for the 'name' field.
 * @endcode
 */
PSLIST_HEADER SsdtShadowHookingDetection(HANDLE hDevice, PDWORD nbEntry);

/**
 * @name    SsdtHookingDetection
 * @brief   This routine returns information about hooked SSDT entries.
 *
 * This API gives informations relative to hooked SSDT entries.
 * NB : To manipulate SLIST_HEADER use PopHookInformationList/PushHookInformationList
 *
 * @param [in] pSsdt A pointer to an KSERVICE_TABLE_DESCRIPTOR.
 * @param [in] pFunctSsdt  A pointer to an array of SSDT entries.
 * @param [in] modBase The base address of module which exported functions contained in pSsdt.
 * @param [in] modSize The image size o this module.
 * @param [out] nbEntry Number of entries in SSDT.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to SLIST_HEADER structure, the head of the single linked list.
 *
 * Example Usage:
 * @code
 *    SsdtHookingDetection(pSsdtAddress, pSsdtAddress->modBase, pSsdtAddress->modSize, NULL); 
 *    // /!\ Never forgotten to clean the list with PopInformationHookList and free for the 'name' field.
 * @endcode
 */
PSLIST_HEADER SsdtHookingDetection(PKSERVICE_TABLE_DESCRIPTOR pSsdt, PDWORD pFunctSsdt, DWORD modBase, DWORD modSize, PDWORD nbEntry);

/**
 * @name    BuildSystemApiNameTable
 * @brief   This routine returns a table which contained Syscall Name.
 *
 * This API gives System Syscall Name into a string table.
 *
 * @param [in] pTable Pointer on the table.
 * @param [in] nb Number of SSDT System entries.
 *
 * @retval FALSE  An error occured.
 * @retval TRUE  Function succeed.
 *
 * Example Usage:
 * @code
 *    BuildSystemApiNameTable(pTable, nb); 
 * @endcode
 */
BOOL BuildSystemApiNameTable(PCHAR* pTable, DWORD nb);

#endif