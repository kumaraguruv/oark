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
 */

#ifndef _SSDT_H
#define _SSDT_H


/*
    Organization of Wdm.h, Ntddk.h, and Ntifs.h
    http://msdn.microsoft.com/en-us/library/ff554739%28v=VS.85%29.aspx
*/
#include <wdm.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)
    typedef struct
    {
        PULONG Base;
        PULONG Count;
        ULONG Limit;
        PUCHAR Number;
    } KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
#pragma pack()

/* 
    /!\ This pointer isn't exported in x64 kernels
    http://www.msuiche.net/papers/Windows_Vista_64bits_and_unexported_kernel_symbols.pdf
*/
__declspec(dllimport) KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;




/**
 * @name    GetSsdtSystemBaseAddress
 * @brief   Retrieves SSDT System base address.
 *
 * This API gives base address of SSDT System.
 *
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

#ifdef __cplusplus
}
#endif

#endif