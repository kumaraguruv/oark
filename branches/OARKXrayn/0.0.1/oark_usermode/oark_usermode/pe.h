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
#ifndef _PE_H_
#define _PE_H_

#include <windows.h>

#define OptHdrMinSize(field) ((INT)(&pImgNtHeads->OptionalHeader.##field) + sizeof(pImgNtHeads->OptionalHeader.##field) - (INT)(&pImgNtHeads->OptionalHeader))
#define IsFieldPresent(field) (sizeOpt >= (OptHdrMinSize(field)))

typedef enum FIELD_PE
{
    MACHINE = 0,
    NMB_OF_SECTIONS,
    CHARACTERISTICS,
    MAJ_LINKER_V,
    MIN_LINKER_V,
    SIZE_OF_CODE,
    SIZE_OF_INITIALIZED_DATA,
    SIZE_OF_UNINITIALIZED_DATA,
    ADDR_OF_EP,
    BASE_OF_CODE,
    BASE_OF_DATA,
    IMAGE_BASE,
    SECTION_ALIGNMENT,
    FILE_ALIGNMENT
    /* [...] */
} FIELD_PE;

/**
 * @name    GetDosHeader
 * @brief   Retrieves DOS Header.
 *
 * This API gives DOS Header structure.
 *
 * @param [in] hBin Pointer of the binary in memory.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a IMAGE_DOS_HEADER structure.
 *
 * Example Usage:
 * @code
 *    GetDosHeader(hBin);
 * @endcode
 */
PIMAGE_DOS_HEADER GetDosHeader(HANDLE hBin);

/**
 * @name    GetNtHeaders
 * @brief   Retrieves NT Headers.
 *
 * This API gives NT Headers structure.
 *
 * @param [in] hBin Pointer of the binary in memory.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a IMAGE_NT_HEADERS structure.
 *
 * Example Usage:
 * @code
 *    GetNtHeaders(hBin);
 * @endcode
 */
PIMAGE_NT_HEADERS GetNtHeaders(HANDLE hBin);

/**
 * @name    GetExportTableDirectory
 * @brief   Retrieves the EAT.
 *
 * This API gives EAT structure.
 *
 * @param [in] hBin Pointer of the binary in memory.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to a IMAGE_EXPORT_DIRECTORY structure.
 *
 * Example Usage:
 * @code
 *    GetExportTableDirectory(hBin);
 * @endcode
 */
PIMAGE_EXPORT_DIRECTORY GetExportTableDirectory(HANDLE hBin);

/**
 * @name    GetExportedSymbol
 * @brief   Retrieves exported symbol RVA.
 *
 * This API gives the (R)VA of an exported symbol.
 *
 * @param [in] hBin Pointer of the binary in memory.
 * @param [in] pNameSymbol Name of the exported symbol.
 * @param [in] TRUE if you want a VA, FALSE if you do not want.
 *
 * @retval NULL  An error occured.
 * @retval other  A (R)VA to the symbol pNameSymbol exported.
 *
 * Example Usage:
 * @code
 *    GetExportedSymbol(hBin, "smth", TRUE);
 * @endcode
 */
PDWORD GetExportedSymbol(HANDLE hBin, PCHAR pNameSymbol, BOOL rva);

/**
 * @name    GetPEField
 * @brief   Retrieves a PE field.
 *
 * This API gives a PE field.
 *
 * @param [in] hBin Pointer of the binary in memory.
 * @param [in] pNameSymbol Name of the exported symbol.
 *
 * @retval NULL  An error occured.
 * @retval other  A RVA to the symbol pNameSymbol exported.
 *
 * Example Usage:
 * @code
 *    GetPEField(hBin, IMAGE_BASE);
 * @endcode
 */
PVOID GetPEField(HANDLE hBin, FIELD_PE field);

#endif