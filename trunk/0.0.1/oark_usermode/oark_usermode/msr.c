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
 * @file   msr.c
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  MSR stuff.
 *
 */
#include "msr.h"
#include "debug.h"
#include "driverusr.h"
#include "render.h"
#include "modules.h"

STATUS_t CheckSysenterHookDetection(FUNC_ARGS_t * args, FUNC_ARGS_GLOBAL_t * globals)
{
    PREPORT_SECTION idSysenter = NULL;
    STATUS_t ret = ST_OK;
    DWORD msrEip = 0;
    PCHAR pMod = NULL;
    BOOL isHooked = FALSE;

    __try
    {
        idSysenter = RenderAddSection("SYSENTER Hooking Detection");

        msrEip = (DWORD)ReadMSRSysenterEIP(globals->hdevice);
        if(msrEip == 0)
        {
            OARK_ERROR("ReadMSRSysenterEIP failed");
            ret = ST_ERROR;
            goto clean;
        }

        RenderAddEntry(idSysenter, "IA32_MSR_EIP Value", msrEip, FORMAT_HEX);
        pMod = IsAddressInADriver(msrEip);

        if(pMod == NULL)
            OARK_ERROR("IsAddressInADriver failed")
        else
            RenderAddEntry(idSysenter, "Address points in", pMod, FORMAT_STR_ASCII);

        if(IsAddressInKernel(msrEip) == FALSE)
            isHooked = TRUE;

        RenderAddEntry(idSysenter, "Is Hooked", ((isHooked)?"Yes":"No"), FORMAT_STR_ASCII);

        clean:
        if(pMod != NULL)
            free(pMod);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return ret;
}

DWORD64 ReadMSR(HANDLE hDevice, DWORD msrId)
{
    READ_KERN_MEM_t read_kern_mem = {0};
    DWORD64 ret = 0;

    __try
    {
        read_kern_mem.dst_address = &ret;
        read_kern_mem.size = sizeof(DWORD64);
        read_kern_mem.src_address = (PVOID)msrId;
        read_kern_mem.type = SYM_TYP_READ_MSR;

        if(IOCTLReadKernMem(hDevice, &read_kern_mem) == NULL)
            OARK_IOCTL_ERROR();
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
        OARK_EXCEPTION();

    return ret;
}