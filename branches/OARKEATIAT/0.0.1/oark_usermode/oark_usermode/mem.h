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
 * @file   mem.h
 * @Author 0vercl0k@tuxfamily.org
 * @date   December, 2010
 * @brief  Memory stuff.
 *
 */

#ifndef _MEM_H_
#define _MEM_H_

#include <windows.h>

/**
 * @name    ReadRemoteMemory
 * @brief   Read the memory of a remote process.
 *
 * This API reads the memory of a remote process.
 *
 * @param [in] pid Process-Ident.
 * @param [in] VA Virtual Address where you want to read.
 * @param [in] size Size of data to dump.
 *
 * @retval NULL An error occured.
 *         other A pointer to the dumped memory.
 *
 * Example Usage:
 * @code
 *    mem = ReadRemoteMemory(1337, 0x400000, 10); //Never forgotten to free ptr !
 * @endcode
 */
PVOID ReadRemoteMemory(DWORD pid, DWORD VA, DWORD size);


/**
 * @name    ReadRemoteString
 * @brief   Read a string in the remote process memory.
 *
 * This API reads a NULL terminated string in the memory of a remote process.
 *
 * @param [in] pid Process-Ident.
 * @param [in] VA Virtual Address of the string.
 *
 * @retval NULL An error occured.
 *         other A pointer to the dumped string.
 *
 * Example Usage:
 * @code
 *    str = ReadRemoteString(1337, 0x400000); //Never forgotten to free ptr !
 * @endcode
 */
PCHAR ReadRemoteString(DWORD pid, DWORD VA);

#endif