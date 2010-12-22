#include "render.h"
#include "list.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

PVOID RenderAllocator(DWORD size)
{
    PVOID ret = NULL;
    __try
    {
        ret = malloc(size);
        if(ret == NULL)
        {
            OARK_ALLOCATION_ERROR();
            return NULL;
        }
        
        //printf("Allocating @0x%.8X\n", ret);
        ZeroMemory(ret, size);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_ALLOCATION_ERROR();

    return ret;
}

VOID RenderFree(PVOID ptr)
{
    __try
    {
        if(ptr == NULL)
            return;

        free(ptr);
        //printf("Freeing @0x%.8X\n", ptr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

VOID RenderCleanEntries(PREPORT_INFORMATION pInf)
{
    PREPORT_INFORMATION pInfBack = NULL;

    __try
    {
        while(pInf != NULL)
        {
            pInfBack = pInf;
            if(pInf->pInformation.isFreeable)
                RenderFree(pInf->pInformation.ptr);

            pInf = pInf->nxt;
            RenderFree(pInfBack);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

VOID RenderCleanList()
{
    PREPORT_SUBSECTION pSubSect = NULL, pSubSectBack = NULL;
    PREPORT_SECTION pSectHead = NULL, pSectBack = NULL;

    __try
    {
        pSectHead = RenderGetList();
        while(pSectHead != NULL)
        {
            pSectBack = pSectHead;

            //Clean entries relative to a section
            RenderCleanEntries(pSectHead->pEntries);

            pSubSect = pSectHead->pSubSect;
            //SubSection of a section
            while(pSubSect != NULL)
            {
                pSubSectBack = pSubSect;

                //Clean entries relative to a subsection
                RenderCleanEntries(pSubSect->pEntries);    

                RenderFree(pSubSect->pName);
                pSubSect = pSubSect->nxt;
                RenderFree(pSubSectBack);
            }
                        
            RenderFree(pSectHead->pName);
            pSectHead = pSectHead->nxt;
            RenderFree(pSectBack);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

PREPORT_SECTION RenderAddSection(PCHAR pName)
{
    static PREPORT_SECTION pRoot = NULL, pLastSect = NULL;
    PREPORT_SECTION *ppSec, pSec = NULL;

    __try
    {
        if(pName == NULL)
            return pRoot;

        if(pRoot == NULL)
            ppSec = &pRoot;
        else
            ppSec = &(pLastSect->nxt);

        *ppSec = RenderAllocator(sizeof(REPORT_SECTION));
        if(*ppSec == NULL)
        {
            OARK_ERROR("RenderAllocator failed");
            return NULL;
        }

        pSec = *ppSec;

        pSec->pName = RenderAllocator(sizeof(REPORT_INFORMATION));
        if(pSec->pName == NULL)
        {
            OARK_ERROR("RenderAllocator failed");
            return NULL;
        }

        pSec->pName->format = FORMAT_STR_ASCII;
        pSec->pName->pDesc = pName;

        pLastSect = pSec;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSec;
}

PREPORT_SUBSECTION RenderAddSubSection(PREPORT_SECTION pSec, PCHAR pName)
{
    PREPORT_SUBSECTION *ppLastSubSec = NULL, pSubSec = NULL;

    __try
    {
        if(pSec->pSubSect == NULL)
            ppLastSubSec = &pSec->pSubSect;
        else
        {
            for(ppLastSubSec = &(pSec->pSubSect); (*ppLastSubSec)->nxt != NULL; ppLastSubSec = &((*ppLastSubSec)->nxt));
                ppLastSubSec = &((*ppLastSubSec)->nxt);
        }

        *ppLastSubSec = RenderAllocator(sizeof(REPORT_SUBSECTION));
        if(*ppLastSubSec == NULL)
        {
            RenderCleanList();
            OARK_ERROR("RenderAllocator failed");
            return NULL;
        }

        pSubSec = *ppLastSubSec;
        pSubSec->pName = RenderAllocator(sizeof(REPORT_INFORMATION));
        if(pSubSec->pName == NULL)
        {
            RenderCleanList();
            OARK_ERROR("RenderAllocator failed");
            return NULL;
        }

        pSubSec->pName->pDesc = pName;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return pSubSec;
}

VOID renderAddEntry(PREPORT_SECTION pSec, PCHAR pDesc, PVOID pInfo, FORMAT_TYPE format)
{
    PREPORT_INFORMATION *ppLastEntry = NULL, pEntry = NULL;

    __try
    {
        if(pSec->pEntries == NULL)
            ppLastEntry = &pSec->pEntries;
        else
        {
            for(ppLastEntry = &(pSec->pEntries); (*ppLastEntry)->nxt != NULL; ppLastEntry = &((*ppLastEntry)->nxt));
            ppLastEntry = &((*ppLastEntry)->nxt);
        }

        *ppLastEntry = RenderAllocator(sizeof(REPORT_INFORMATION));
        if(*ppLastEntry == NULL)
        {
            RenderCleanList();
            OARK_ERROR("RenderAllocator failed");
            return;
        }

        pEntry = *ppLastEntry;

        pEntry->format = format;
        pEntry->pDesc = pDesc;
        if(format == FORMAT_STR_ASCII)
        {
            pEntry->pInformation.isFreeable = TRUE;
            pEntry->pInformation.ptr = RenderAllocator(strlen(pInfo) + 1);
            if(pEntry->pInformation.ptr == NULL)
            {
                RenderCleanList();
                OARK_ERROR("RenderAllocator failed");
                return;
            }
            memcpy(pEntry->pInformation.ptr, pInfo, strlen(pInfo));
        }
        else
            pEntry->pInformation.ptr = pInfo;        

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();
}

VOID RenderAddSeparator(PREPORT_SECTION pSec)
{
    renderAddEntry(pSec, "-------", NULL, FORMAT_SEPARATOR);
}

PREPORT_SECTION RenderGetList()
{
    return RenderAddSection(NULL);
}

PREPORT_SECTION RenderInitialization()
{
    PREPORT_SUBSECTION idSubInf = NULL;
    PCHAR pDate = NULL;
    DWORD sizeDate = 0;
    time_t t = {0};

    __try
    {
        t = time(NULL);
        idSubInf = RenderAddSection("oark - The Open Source Anti Rootkit");
        RenderAddEntry(idSubInf, "URL", "http://code.google.com/p/oark/", FORMAT_STR_ASCII);
        RenderAddEntry(idSubInf, "Main Developers", "David Reguera Garcia - Dreg@fr33project.org", FORMAT_STR_ASCII);
        RenderAddEntry(idSubInf, "Comitters", "Axel Souchet - 0vercl0k@tuxfamily.org", FORMAT_STR_ASCII);
        RenderAddEntry(idSubInf, "Greetings", "DiabloNova (RootkitUnhooker inspiration)", FORMAT_STR_ASCII);

        RenderAddSeparator(idSubInf);
        RenderAddEntry(idSubInf, "Report Date", ctime(&t), FORMAT_STR_ASCII);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return idSubInf;
}