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
 * @file   list.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  List entry stuff.
 *
 */
#ifndef _LIST_H_
#define _LIST_H_

#include <windows.h>

typedef struct
{
    SLIST_ENTRY SListEntry;
    DWORD id;
    DWORD addr;
    PCHAR name;
}HOOK_INFORMATION, *PHOOK_INFORMATION;

/**
 * @name    PushHookInformationEntry
 * @brief   This routine allows you to push an HOOK_INFORMATION structure from a list.
 *
 * This API pops a structure HOOK_INFORMATION from the single linked list.
 *
 * @param [in] pListHead  A pointer to a SLIST_HEADER which is the single linked list's head.
 * @param [in] entry  A pointer to a HOOK_INFORMATION structure.
 *
 * Example Usage:
 * @code
 *    PushHookInformationEntry(pListHead, pHookInfo); 
 * @endcode
 */
VOID PushHookInformationEntry(PSLIST_HEADER pListHead, PHOOK_INFORMATION entry);

/**
 * @name    PopHookInformationEntry
 * @brief   This routine allows you to pop an HOOK_INFORMATION structure from a list.
 *
 * This API pops a structure HOOK_INFORMATION from the single linked list.
 *
 * @param [in] pListHead  A pointer to a SLIST_HEADER which is the single linked list's head.
 *
 * @retval NULL  The list is empty.
 * @retval other  A pointer to the driver name.
 *
 * Example Usage:
 * @code
 *    PHOOK_INFORMATION pHook = PopHookInformationEntry(pListHead); 
 *    // /!\ Never forgotten to free the pointer and the 'name' field.
 * @endcode
 */
PHOOK_INFORMATION PopHookInformationEntry(PSLIST_HEADER pListHead);

/**
 * @name    PopHookInformationEntry
 * @brief   This routine cleans a list.
 *
 * This API cleans a single linked list..
 *
 * @param [in] pListHead  A pointer to a SLIST_HEADER which is the single linked list's head.
 *
 * Example Usage:
 * @code
 *    CleanHookInfoList(pListHead); 
 * @endcode
 */
VOID CleanHookInfoList(PSLIST_HEADER pListHead);

#endif