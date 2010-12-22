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
 * @file   report.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Report Generation.
 *
 */
#ifndef _REPORT_H_
#define _REPORT_H_

#include <windows.h>
#include <stdio.h>
#include "render.h"

#define OARK_FILENAME_LOG "report-oark.log"

typedef enum
{
    OUTPUT_FORMAT_XML = 0,
    OUTPUT_FORMAT_TXT,
    OUTPUT_FORMAT_HTML
} OUTPUT_FORMAT;

typedef enum
{
    OUTPUT_DST_STDOUT = 0,
    OUTPUT_DST_FILE
} OUTPUT_DST;

/**
 * @name    DisplaySubSectionText
 * @brief   This routine handles subsection text reporting.
 *
 * This API formats correctly a subsection for a text reporting.
 *
 * @param [in] pName SubSection name.
 * @param [in] pOut  The output file.
 *
 * Example Usage:
 * @code
 *    DisplaySubSectionText("SubSect1", stdout); 
 * @endcode
 */
VOID DisplaySubSectionText(PCHAR pName, FILE* pOut);

/**
 * @name    DisplaySectionText
 * @brief   This routine handles section text reporting.
 *
 * This API formats correctly a section for a text reporting.
 *
 * @param [in] pName Section name.
 * @param [in] pOut  The output file.
 *
 * Example Usage:
 * @code
 *    DisplaySectionText("Sect1", stdout); 
 * @endcode
 */
VOID DisplaySectionText(PCHAR pName, FILE* pOut);

/**
 * @name    DisplayEntriesText
 * @brief   This routine handles entries for text reporting.
 *
 * This API formats correctly entries for a text reporting.
 *
 * @param [in] pName Section name.
 * @param [in] pOut  The output file.
 *
 * @retval x The number of entries.
 *
 * Example Usage:
 * @code
 *    DisplayEntriesText(pInf, stdout); 
 * @endcode
 */
DWORD DisplayEntriesText(PREPORT_INFORMATION pInfo, FILE* pOut);

/**
 * @name    MakeReportText
 * @brief   This routine makes the text reporting.
 *
 * This API formats correctly RenderList for a text reporting.
 *
 * @param [in] pRootList The RenderList.
 * @param [in] pOut  The output file.
 *
 * Example Usage:
 * @code
 *    MakeReportText(pRoot, stdout); 
 * @endcode
 */
VOID MakeReportText(PREPORT_SECTION pRootList, FILE* pOut);

/**
 * @name    MakeReport
 * @brief   This routine makes the reporting.
 *
 * This API formats correctly RenderList for a report.
 *
 * @param [in] outForm The output format, HTML/XML/TXT.
 * @param [in] outDst  The output destination, STDOUT/FILE.
 *
 * Example Usage:
 * @code
 *    MakeReport(OUTPUT_FORMAT_TXT, OUTPUT_DST_STDOUT); 
 * @endcode
 */
VOID MakeReport(OUTPUT_FORMAT outForm, OUTPUT_DST outDst);

#endif