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
 * @file   unicode.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Unicode stuff.
 *
 */
#include "unicode.h"
#include "debug.h"

PCHAR UnicodeToAnsi(PWSTR pStrW)
{
    PCHAR pStrA = NULL;
    DWORD sizeA = 0;

    __try
    {
        sizeA = WideCharToMultiByte(CP_ACP,
        0,
        pStrW,
        -1,
        NULL,
        0,
        NULL,
        NULL
        );

        if(sizeA == 0)
        {
            OARK_ERROR("WideCharToMultiByte failed");
            return NULL;
        }

        pStrA = (PCHAR)malloc(sizeA * sizeof(CHAR));
        if(pStrA == NULL)
        {
            OARK_ALLOCATION_ERROR();
            return NULL;
        }

        memset(pStrA, 0, sizeA);
        WideCharToMultiByte(CP_ACP,
            0,
            pStrW,
            -1,
            pStrA,
            sizeA,
            NULL,
            NULL
            );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pStrA;
}