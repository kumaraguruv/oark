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
 * @file   report.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Report Generation.
 *
 */
#include "report.h"
#include "debug.h"

VOID DisplaySectionText(PCHAR pName, FILE* pOut)
{
    CONSOLE_SCREEN_BUFFER_INFO consInfo = {0};
    DWORD i = 0, longSize = 0, offset = 0;

    __try
    {
        if(pOut != stdout)
            longSize = DEFAULT_NB_COLUMN_OUTPUT;
        else
        {
            GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consInfo);
            longSize = consInfo.dwMaximumWindowSize.X;
        }

        offset = (longSize - (strlen(pName)+2)) / 2;
        for(; i < offset; ++i)
            fprintf(pOut, "=");

        fprintf(pOut, " %s ", pName);
        i += strlen(pName) + 2;

        for(; i < longSize; ++i)
            fprintf(pOut, "=");

        if(pOut != stdout)
            fprintf(pOut, "\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

VOID DisplaySubSectionText(PCHAR pName, FILE* pOut)
{
    CONSOLE_SCREEN_BUFFER_INFO consInfo = {0};
    DWORD i = 0, longSize = 0, offset = 0;

    __try
    {
        if(pOut != stdout)
            longSize = DEFAULT_NB_COLUMN_OUTPUT;
        else
        {
            GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consInfo);
            longSize = consInfo.dwMaximumWindowSize.X;
        }

        offset = (longSize - strlen(pName)) / 2;
        fprintf(pOut, "**");
        for(i = 2; i < offset; ++i)
            fprintf(pOut, " ");

        fprintf(pOut, "%s", pName);
        i += strlen(pName);

        for(; i < longSize - 2; ++i)
            fprintf(pOut, " ");

        fprintf(pOut, "**");
        if(pOut != stdout)
            fprintf(pOut, "\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

DWORD DisplayEntriesText(PREPORT_INFORMATION pInfo, FILE* pOut)
{
    DWORD ret = 0;

    __try
    {
        for(; pInfo != NULL; pInfo = pInfo->nxt, ret++)
        {
            if(pInfo->format == FORMAT_SEPARATOR)
                fprintf(pOut, pInfo->pDesc);
            else
            {
                fprintf(pOut, " >%s: ", pInfo->pDesc);
                switch(pInfo->format)
                {
                case FORMAT_HEX:
                    fprintf(pOut, "%.8Xh", pInfo->pInformation.ptr);
                    break;

                case FORMAT_STR_ASCII:
                    fprintf(pOut, "%s", pInfo->pInformation.ptr);
                    break;

                case FORMAT_DEC:
                    fprintf(pOut, "%d", pInfo->pInformation.ptr);
                    break;
                }
            }

            fprintf(pOut, "\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return ret;
}

VOID MakeReportText(PREPORT_SECTION pRootList, FILE* pOut)
{
    PREPORT_SUBSECTION pSubSect = NULL;

    __try
    {
        for(; pRootList != NULL; pRootList = pRootList->nxt)
        {
            DisplaySectionText(pRootList->pName->pDesc, pOut);

            //Entries relative to a section
            if(DisplayEntriesText(pRootList->pEntries, pOut) != 0)
                fprintf(pOut, "\n");

            //SubSection
            for(pSubSect = pRootList->pSubSect; pSubSect != NULL; pSubSect = pSubSect->nxt)
            {
                DisplaySubSectionText(pSubSect->pName->pDesc, pOut);

                //Entries relative to a subsection
                if(DisplayEntriesText(pSubSect->pEntries, pOut) != 0)
                    fprintf(pOut, "\n");
            }

            fprintf(pOut, "\n");
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

VOID MakeReport(OUTPUT_FORMAT outForm, OUTPUT_DST outDst, BOOLEAN remove )
{
    PREPORT_SECTION pRootList = NULL;
    FILE *pFile = NULL;
    __try
    {
        pRootList = RenderGetList();
        if(pRootList == NULL)
        {
            OARK_ERROR("RenderList empty");
            return;
        }

        switch(outForm)
        {
            case OUTPUT_FORMAT_TXT:
                if(outDst == OUTPUT_DST_STDOUT)
                    MakeReportText(pRootList, stdout);
                else
                {
                    pFile = fopen("./" OARK_FILENAME_LOG, "w");
                    if(pFile == NULL)
                    {
                        OARK_ERROR("fopend failed");
                        return;
                    }

                    MakeReportText(pRootList, pFile);
                    fclose(pFile);
                }
                
            break;

            case OUTPUT_FORMAT_HTML:
            case OUTPUT_FORMAT_XML:
                OARK_ERROR("Format not supported yet");
                return;
        }
        if ( remove )
            RenderCleanList();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}