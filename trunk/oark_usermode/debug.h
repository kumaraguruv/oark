/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>
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

#ifndef _DEBUG_H__
#define _DEBUG_H__

#include <windows.h>
#include <stdio.h>
#include "common.h"

extern BOOL debug;

#define OARK_EXCEPTION(){                                \
    DisplayExceptionMsg(__FUNCTION__, __LINE__);         \
}

#define OARK_ERROR(x) {                                  \
    DisplayErrorMsg(x, __FUNCTION__, __LINE__);          \
}

#define OARK_ALLOCATION_ERROR() {                        \
    DisplayAllocationFailureMsg(__FUNCTION__, __LINE__); \
}

#define OARK_IOCTL_ERROR() {                             \
    DisplayIOCTLFailureMsg(__FUNCTION__, __LINE__);      \
}

/**
 * @name    DisplayErrorMsg
 * @brief   This routine displays error message.
 *
 * This API displays information about an error.
 *
 * @param [in] pMsg A message.
 * @param [in] pFunctName Function Name.
 * @param [in] line Line number.
 *
 * Example Usage:
 * @code
 *    DisplayErrorMsg("MemoryAllocationFail", "test", 1337);
 * @endcode
 */
VOID DisplayErrorMsg(PCHAR pMsg, PCHAR pFunctName, DWORD line);

/**
 * @name    DisplayAllocationFailureMsg
 * @brief   This routine displays memory allocation error message.
 *
 * This API displays information about a memory allocation error.
 *
 * @param [in] pFunctName Function Name.
 * @param [in] line Line number.
 *
 * Example Usage:
 * @code
 *    DisplayAllocationFailureMsg("test", 1337);
 * @endcode
 */
VOID DisplayAllocationFailureMsg(PCHAR pFunctName, DWORD line);

/**
 * @name    DisplayIOCTLFailureMsg
 * @brief   This routine displays IOCTLReadKernMem error message.
 *
 * This API displays information about a IOCTLReadKernMem error.
 *
 * @param [in] pFunctName Function Name.
 * @param [in] line Line number.
 *
 * Example Usage:
 * @code
 *    DisplayIOCTLFailureMsg("test", 1337);
 * @endcode
 */
VOID DisplayIOCTLFailureMsg(PCHAR pFunctName, DWORD line);

/**
 * @name    DisplayExceptionMsg
 * @brief   This routine displays an error message when exception is catched.
 *
 * This API displays information when an exception is catched.
 *
 * @param [in] pFunctName Function Name.
 * @param [in] line Line number.
 *
 * Example Usage:
 * @code
 *    DisplayExceptionMsg("test", 1337);
 * @endcode
 */
VOID DisplayExceptionMsg(PCHAR pFunctName, DWORD line);

STATUS_t EnableDebugPrivilege( void );

#endif /* _DEBUG_H__ */