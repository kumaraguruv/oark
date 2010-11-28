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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <WinDef.h>

#define OARK_VERSION "0.0.1"

#define DEVICE_NAME			"\\Device\\OARK_DRIVER"
#define SYMLINK_NAME		"\\DosDevices\\OARK_DRIVER"
#define NAMEOF_DEVICE       "\\\\.\\OARK_DRIVER"
#define DRIVER_NAME         "OARK_DRIVER.SYS"
#define SERVICE_NAME        "OARK_DRIVER"
#define OARK_IOCTL_CHANGE_MODE \
	CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

typedef enum STATUS_e
{
	ST_ERROR = 0,
	ST_OK

} STATUS_t;

typedef enum MEM_SYM_TYP_e
{
	SYM_TYP_NULL = 0,
	SYM_TYP_KPCR,
	SYM_TYP_IDT,
	SYM_TYP_GDT,
	SYM_TYP_PSLOUPRBYID,
	SYM_TYP_OBDEREFOBJ

} MEM_SYM_TYP_t;

typedef struct READ_KERN_MEM_s
{
	void           * src_address;
	DWORD            size;
	MEM_SYM_TYP_t    type;
	void           * dst_address;

} READ_KERN_MEM_t;

#pragma pack(1)

typedef struct _IDT_DESCRIPTOR
{
	WORD offset00_15; 
	WORD selector; 
	BYTE unused:5; 
	BYTE zeroes:3; 
	BYTE gateType:5; 
	BYTE DPL:2; 
	BYTE P:1;
	WORD offset16_31; 
} IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;

typedef struct _IDTR
{
	WORD nBytes;
	WORD baseAddressLow;
	WORD baseAddressHi;
} IDTR;

#pragma pack()

#define IDT_HARDCODE_SIZE 0x7FF

#define MAKEDWORD(a, b)      ((unsigned int)(((WORD)(a)) | ((WORD)((WORD)(b))) << 16))  

#endif /* __COMMON_H__ */