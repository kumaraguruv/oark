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
#include "mem.h"

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

PDWORD GetExportedSymbol(HANDLE hBin, PCHAR pNameSymbol, BOOL rva)
{
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = NULL;
    PIMAGE_DOS_HEADER pImgDosHead = NULL;
    PDWORD pAddrExportFunct, pExportNames = NULL, pAddrExportedSym = NULL;
    PSHORT pAddrNamesOrd = NULL;
    PCHAR pNameExport = NULL;
    DWORD i = 0;

    __try
    {
        pImgExpDir = GetExportTableDirectory(hBin);
        pImgDosHead = GetDosHeader(hBin);

        pExportNames = (PDWORD)((DWORD)pImgDosHead + pImgExpDir->AddressOfNames);
        pAddrExportFunct = (PDWORD)((DWORD)pImgDosHead + pImgExpDir->AddressOfFunctions);
        pAddrNamesOrd = (PSHORT)((DWORD)pImgDosHead + pImgExpDir->AddressOfNameOrdinals);

        for(; i < pImgExpDir->NumberOfFunctions; ++i)
        {
            pNameExport = (PCHAR)((DWORD)pImgDosHead + pExportNames[i]);
            if(strcmp(pNameExport, pNameSymbol) == 0)
            {
                pAddrExportedSym = (PDWORD)(pAddrExportFunct[pAddrNamesOrd[i]]);
                if(rva == TRUE)
                    (DWORD)pAddrExportedSym += (DWORD)pImgDosHead;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pAddrExportedSym;
}

PVOID GetPEField(HANDLE hBin, FIELD_PE fieldPe)
{
    PIMAGE_NT_HEADERS pImgNtHeads = NULL;
    PIMAGE_DOS_HEADER pImgDosHead = NULL;
    PVOID field = 0;
    DWORD sizeOpt = 0;

    __try
    {
        pImgNtHeads = GetNtHeaders(hBin);
        pImgDosHead = GetDosHeader(hBin);
        sizeOpt = pImgNtHeads->FileHeader.SizeOfOptionalHeader;

        switch(fieldPe)
        {
            case MACHINE:
                field = (PVOID)pImgNtHeads->FileHeader.Machine;
            break;

            case NMB_OF_SECTIONS:
                field = (PVOID)pImgNtHeads->FileHeader.NumberOfSections;
            break;

            case CHARACTERISTICS:
                field = (PVOID)pImgNtHeads->FileHeader.Characteristics;
            break;

            case MAJ_LINKER_V:
                if(IsFieldPresent(MajorLinkerVersion))
                    field = (PVOID)pImgNtHeads->OptionalHeader.MajorLinkerVersion;
            break;

            case MIN_LINKER_V:
                if(IsFieldPresent(MinorLinkerVersion))
                    field = (PVOID)pImgNtHeads->OptionalHeader.MinorLinkerVersion;
            break;

            case SIZE_OF_CODE:
                if(IsFieldPresent(SizeOfCode))
                    field = (PVOID)pImgNtHeads->OptionalHeader.SizeOfCode;
            break;

            case SIZE_OF_INITIALIZED_DATA:
                if(IsFieldPresent(SizeOfInitializedData))
                    field = (PVOID)pImgNtHeads->OptionalHeader.SizeOfInitializedData;
            break;

            case SIZE_OF_UNINITIALIZED_DATA:
                if(IsFieldPresent(SizeOfUninitializedData))
                    field = (PVOID)pImgNtHeads->OptionalHeader.SizeOfUninitializedData;
            break;

            case ADDR_OF_EP:
                if(IsFieldPresent(AddressOfEntryPoint))
                    field = (PVOID)pImgNtHeads->OptionalHeader.AddressOfEntryPoint;
            break;

            case BASE_OF_CODE:
                if(IsFieldPresent(BaseOfCode))
                    field = (PVOID)pImgNtHeads->OptionalHeader.BaseOfCode;
            break;

            case BASE_OF_DATA:
                if(IsFieldPresent(BaseOfData))
                    field = (PVOID)pImgNtHeads->OptionalHeader.BaseOfData;
            break;

            case IMAGE_BASE:
                if(IsFieldPresent(ImageBase))
                    field = (PVOID)pImgNtHeads->OptionalHeader.ImageBase;
            break;

            case SECTION_ALIGNMENT:
                if(IsFieldPresent(SectionAlignment))
                    field = (PVOID)pImgNtHeads->OptionalHeader.SectionAlignment;
            break;

            case FILE_ALIGNMENT:
                if(IsFieldPresent(FileAlignment))
                    field = (PVOID)pImgNtHeads->OptionalHeader.FileAlignment;
            break;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return field;
}

PIMAGE_DOS_HEADER GetRemoteDosHeader(DWORD pid, DWORD imgBase)
{
    PIMAGE_DOS_HEADER pImgDosHead = NULL;

    __try
    {
        pImgDosHead = ReadRemoteMemory(pid, imgBase, sizeof(IMAGE_DOS_HEADER));
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pImgDosHead;
}

PIMAGE_NT_HEADERS GetRemoteNtHeaders(DWORD pid, DWORD imgBase)
{
    PIMAGE_DOS_HEADER pImgDosHead = NULL;
    PIMAGE_NT_HEADERS pImgNtHead = NULL;

    __try
    {
        pImgDosHead = GetRemoteDosHeader(pid, imgBase);
        if(pImgDosHead == NULL)
        {
            OARK_ERROR("GetRemoteDosHeader failed");
            goto clean;
        }

        pImgNtHead = ReadRemoteMemory(pid, imgBase + pImgDosHead->e_lfanew, sizeof(IMAGE_NT_HEADERS));
        
        clean:
        if(pImgDosHead != NULL)
            free(pImgDosHead);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pImgNtHead;
}

PIMAGE_EXPORT_DIRECTORY GetRemoteExportTableDirectory(DWORD pid, DWORD imgBase)
{
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = NULL;
    PIMAGE_NT_HEADERS pImgNtHead = NULL;  

    __try
    {
        pImgNtHead = GetRemoteNtHeaders(pid, imgBase);
        if(pImgNtHead == NULL)
        {
            OARK_ERROR("GetRemoteNtHeaders failed");
            goto clean;
        }

        if(pImgNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
            pImgExportDir = ReadRemoteMemory(pid,
                imgBase + pImgNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                sizeof(IMAGE_EXPORT_DIRECTORY)
                );

        clean:
        if(pImgNtHead != NULL)
            free(pImgNtHead);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pImgExportDir;
}