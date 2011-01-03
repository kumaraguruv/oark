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
 * @file   mem.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Memory stuff.
 *
 */
#include "mem.h"
#include "debug.h"

PVOID ReadRemoteMemory(DWORD pid, DWORD VA, DWORD size)
{
    HANDLE hProcess = NULL;
    PVOID pMem = NULL;
    BOOL ret = FALSE;

    __try
    {
        hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if(hProcess == NULL)
        {
            OARK_ERROR("OpenProcess failed");
            goto clean;
        }
        
        pMem = malloc(size);
        if(pMem == NULL)
        {
            OARK_ALLOCATION_ERROR();
            goto clean;
        }

        ZeroMemory(pMem, size);
        ret = ReadProcessMemory(hProcess,
            (PVOID)VA,
            pMem,
            size,
            NULL
        );

        if(ret == FALSE)
        {
            OARK_ERROR("ReadProcessMemory failed");
            goto clean;
        }

        clean:
        if(hProcess != NULL)
            CloseHandle(hProcess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pMem;
}

PCHAR ReadRemoteString(DWORD pid, DWORD VA)
{
    PCHAR pStr = NULL, pChr = NULL, pTmp = NULL;
    CHAR chr = 1;
    DWORD id = 0, size = 0;

    __try
    {
        while(chr != 0)
        {
            pTmp = realloc(pStr, ++size);
            if(pTmp == NULL)
            {
                OARK_ALLOCATION_ERROR();
                free(pStr);
                return NULL;
            }
            else
                pStr = pTmp;

            pChr = ReadRemoteMemory(pid, VA++, sizeof(char));
            if(pChr == NULL)
            {
                OARK_ERROR("ReadRemoteMemory failed");
                free(pStr);
                return NULL;
            }
                       
            pStr[id++] = *pChr;
            chr = *pChr;
            free(pChr);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pStr;
}