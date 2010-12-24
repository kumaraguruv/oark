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
 * @file   render.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Render API.
 *
 */
#ifndef _RENDER_H_
#define _RENDER_H_

#include <windows.h>
#include <stdio.h>


#define DEFAULT_NB_COLUMN_OUTPUT 81
#define RenderAddEntry(a, b, c, d) renderAddEntry(a, b, (PVOID)(c), d)

typedef enum
{
    FORMAT_STR_ASCII = 0,
    FORMAT_STR_UNICODE,
    FORMAT_HEX,
    FORMAT_DEC,
    FORMAT_SEPARATOR
} FORMAT_TYPE;

typedef struct  
{
    PVOID ptr;
    unsigned char isFreeable;
}REPORT_POINTER, *PREPORT_POINTER;

typedef struct _REPORT_INFORMATION_
{
    PCHAR pDesc;
    REPORT_POINTER pInformation;
    FORMAT_TYPE format;
    struct _REPORT_INFORMATION_* nxt;
} REPORT_INFORMATION, *PREPORT_INFORMATION;

typedef struct _REPORT_SECTION_
{
    PREPORT_INFORMATION pName; //If (sub)section => name of (sub)section else null
    PREPORT_INFORMATION pEntries; //pointer on entries

    struct _REPORT_SECTION_* pSubSect;
    struct _REPORT_SECTION_* nxt;
} REPORT_SECTION, REPORT_SUBSECTION,
 *PREPORT_SECTION, *PREPORT_SUBSECTION;

/**
 * @name    RenderInitialization
 * @brief   This routine initializes RenderList with a small header.
 *
 * This API adds a small-header to the futur generated report.
 *
 * @retval NULL  An error occured.
 * @retval other A pointer on the SECTION added.
 *
 * Example Usage:
 * @code
 *    RenderInitialization(); 
 * @endcode
 */
PREPORT_SECTION RenderInitialization();

/**
 * @name    RenderAllocator
 * @brief   This routine handles memory allocations of the Render List.
 *
 * This API manages memory allocations of the Render List.
 *
 * @param [in] size  Size of memory to allocate.
 *
 * @retval NULL An error occured.
 * @retval other A pointer on the memory space.
 *
 * Example Usage:
 * @code
 *    RenderAllocator(sizeof(REPORT_SECTION)); 
 * @endcode
 */
PVOID RenderAllocator(DWORD size);

/**
 * @name    RenderFree
 * @brief   This routine free a memory allocation.
 *
 * This API gives you a simple way to release memory allocated by
 * RenderAllocator.
 *
 * @param [in] ptr  Memory pointer that needs to be unallocated.
 *
 * Example Usage:
 * @code
 *    RenderFree(ptr); 
 * @endcode
 */
VOID RenderFree(PVOID ptr);

/**
 * @name    RenderGetList
 * @brief   This routine returns RenderList address.
 *
 * This API gives you RenderList address.
 *
 * @retval other A pointer on the RenderList.
 *
 * Example Usage:
 * @code
 *    RenderGetList(); 
 * @endcode
 */
PREPORT_SECTION RenderGetList();

/**
 * @name    RenderCleanEntries
 * @brief   This routine cleans single-linked-list of entry.
 *
 * This API allows you to clean memory properly of a list of entry.
 *
 * @param [in] pInf  A pointer to a REPORT_INFORMATION structure.
 *
 * Example Usage:
 * @code
 *    RenderCleanEntries(ptr->pEntries); 
 * @endcode
 */
VOID RenderCleanEntries(PREPORT_INFORMATION pInf);

/**
 * @name    RenderCleanList
 * @brief   This routine cleans the whole RenderList.
 *
 * This API allows you to clean properly the RenderList.
 *
 * Example Usage:
 * @code
 *    RenderCleanList(); 
 * @endcode
 */
VOID RenderCleanList();

/**
 * @name    RenderAddSection
 * @brief   This routine allows you to add a section.
 *
 * This API adds a section to the render.
 *
 * @param [in] pName  The title of the section.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to the SECTION.
 *
 * Example Usage:
 * @code
 *    PREPORT_SECTION idSect1 = RenderAddSection("Sect1"); 
 * @endcode
 */
PREPORT_SECTION RenderAddSection(PCHAR pName);

/**
 * @name    RenderAddSubSection
 * @brief   This routine allows you to add a subsection relative to a section.
 *
 * This API adds a section to the render.
 *
 * @param [in] pSec The section-id.
 * @param [in] pName  The title of the subsection.
 *
 * @retval NULL  An error occured.
 * @retval other  A pointer to the SUBSECTION.
 *
 * Example Usage:
 * @code
 *    PREPORT_SECTION idSubSect1 = RenderAddSubSection(idSect1, "SubSect1"); 
 * @endcode
 */
PREPORT_SUBSECTION RenderAddSubSection(PREPORT_SECTION pSec, PCHAR pName);

/**
 * @name    renderAddEntry
 * @brief   This routine allows you to add an entry relative to a (sub)section.
 *
 * This API adds an entry to the render.
 *
 * @param [in] pSec The (sub)section-id.
 * @param [in] pDesc Description of the field.
 * @param [in] pInfo Information to be displayed.
 * @param [in] format Format of pInfo information.
 *
 * NB: Your entry will be reported like that:
 * pDesc: pInfo (sure, pInfo correctly formatted)
 *
 * Example Usage:
 * @code
 *    PREPORT_SECTION idSubSect1 = renderAddEntry(idSect1, "Base", 0x1337, FORMAT_HEX); 
 * @endcode
 */
VOID renderAddEntry(PREPORT_SECTION pSec, PCHAR pDesc, PVOID pInfo, FORMAT_TYPE format);

/**
 * @name    RenderAddSeparator
 * @brief   This routine adds a simple separator between two entries.
 *
 * This API adds a separator between two entries.
 *
 * @param [in] pSec The section-id.
 *
 * Example Usage:
 * @code
 *    RenderAddSeparator(idSect1); 
 * @endcode
 */
VOID RenderAddSeparator(PREPORT_SECTION pSec);

#endif