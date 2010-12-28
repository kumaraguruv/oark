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
#include "debug.h"
#include "others.h"
#include "driverusr.h"

#define CALL_GATE_32_TYPE 0x1C
#define LDT_TYPE 0x12

#define FIN_CALL_GATES_GDT          (0x01)
#define FIN_CALL_GATES_LDT          (0x02)
#define FIN_CALL_GATES_LDT_EPROCESS (0x04)
#define FIN_CALL_GATES_LDT_FW       (0x08)

#define FIN_CALL_GATES_DEFAULTS          \
    (                                    \
        FIN_CALL_GATES_GDT |             \
        FIN_CALL_GATES_LDT |             \
        FIN_CALL_GATES_LDT_EPROCESS  |   \
        FIN_CALL_GATES_LDT_FW            \
     )

typedef struct FLAG_TABLE_s
{
    DWORD flag_param;
    DWORD flag_desc;

} FLAG_TABLE_t;

typedef struct TYPES_s
{
    DWORD * types;
    DWORD nr;

} TYPES_t;

typedef struct GDTS_s
{
    GDTR gdts;
    DWORD nr;

} GDTS_t;

typedef struct DESCRIPTOR_s
{
    SEG_DESCRIPTOR descriptor;
    DWORD selector;

} DESCRIPTOR_t;

typedef struct DESCRIPTOR_CORE_TAB_s
{
    DESCRIPTOR_t * descriptors;
    DWORD          core;
    DWORD          nr;
    GDTR           gdt;

} DESCRIPTOR_CORE_TAB_t;

typedef struct DESCRIPTOR_CORE_TAB_WNR_s
{
    DESCRIPTOR_CORE_TAB_t * descriptor_table;
    DWORD          nr;

} DESCRIPTOR_CORE_TAB_WNR_t;

STATUS_t CheckCallGates( FUNC_ARGS_t *, FUNC_ARGS_GLOBAL_t * );
BOOLEAN InitTypes( DWORD, TYPES_t * );

#endif /* _CALL_GATES_H__ */