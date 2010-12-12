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
 * @file   list.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  List entry stuff.
 *
 */

#include "list.h"
#include "debug.h"

VOID PushHookInformationEntry(PSLIST_HEADER pListHead, PHOOK_INFORMATION entry)
{
    __try
    {
        InterlockedPushEntrySList(pListHead, &(entry->SListEntry));
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

PHOOK_INFORMATION PopHookInformationEntry(PSLIST_HEADER pListHead)
{
    PSLIST_ENTRY pListEntry = NULL;

    __try
    {
        pListEntry = InterlockedPopEntrySList(pListHead);
        if(pListEntry == NULL)
            return NULL;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return CONTAINING_RECORD(pListEntry, HOOK_INFORMATION, SListEntry);
}

VOID CleanHookInfoList(PSLIST_HEADER pListHead)
{
    PHOOK_INFORMATION pHookInfo = NULL;

    __try
    {
        while( (pHookInfo = PopHookInformationEntry(pListHead)) != NULL)
        {
            if(pHookInfo->name != NULL)
                free(pHookInfo->name);
            free(pHookInfo);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}