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
 * @file   pe.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  PE stuff.
 *
 */
#include "pe.h"
#include "debug.h"

PIMAGE_DOS_HEADER GetDosHeader(HANDLE hBin)
{
    PIMAGE_DOS_HEADER pImgDosHead = NULL;

    __try
    {
        pImgDosHead = (PIMAGE_DOS_HEADER)hBin;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pImgDosHead;
}

PIMAGE_NT_HEADERS GetNtHeaders(HANDLE hBin)
{
    PIMAGE_DOS_HEADER pImgDosHead = NULL;
    PIMAGE_NT_HEADERS pImgNtHead = NULL;

    __try
    {
        pImgDosHead = GetDosHeader(hBin);
        pImgNtHead = (PIMAGE_NT_HEADERS)((DWORD)pImgDosHead + pImgDosHead->e_lfanew);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pImgNtHead;
}

PIMAGE_EXPORT_DIRECTORY GetExportTableDirectory(HANDLE hBin)
{
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = NULL;
    PIMAGE_NT_HEADERS pImgNtHead = NULL;  
    PIMAGE_DOS_HEADER pImgDosHead = NULL;

    __try
    {
        pImgNtHead = GetNtHeaders(hBin);
        pImgDosHead = GetDosHeader(hBin);
        pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pImgDosHead + pImgNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pImgExportDir;
}