/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>

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


#ifndef _CALL_GATES_H__
#define _CALL_GATES_H__

#include <windows.h>
#include "common.h"
#include "others.h"
#include "driverusr.h"
#include "debug.h"

#define CALL_GATE_32_TYPE 0x1C
#define LDT_TYPE 0x12

void CheckCallGatesAndLDTFW( HANDLE );
void GetBaseAndLimit( PSEG_DESCRIPTOR, DWORD *, DWORD * );
void CheckDesc( PSEG_DESCRIPTOR, DWORD, DWORD, HANDLE );

#endif /* _CALL_GATES_H__ */
