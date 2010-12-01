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

#ifndef _PEBHOOKING_H__
#define _PEBHOOKING_H__

#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <Shlwapi.h>
#include "others.h"
#include "debug.h"
#include "vad.h"

typedef struct LDR_USEFULL_s
{
	SLIST_ENTRY SingleListEntry;

	char full_dll_name[(MAX_PATH * 2) + 2];
	char base_dll_name[(MAX_PATH * 2) + 2];
	DWORD ep_without_ba;
	DWORD base_address;
	DWORD size_of_image;
	DWORD time_data_stamp;

} LDR_USEFULL_t;

void CheckDuplicateEntries( PSLIST_HEADER, LDR_USEFULL_t * );
void CheckRawFile( LDR_USEFULL_t * );
int _CheckPEBHooking( HANDLE, DWORD );
STATUS_t CheckPEBHooking( HANDLE );
void ComparePEBEntryVADInfo( LDR_USEFULL_t *, PSLIST_HEADER );
BOOLEAN IsVADStringEqPebStr( char *, char * );
char * RemovePrePATH( char  *, BOOLEAN * );

#endif /* _PEBHOOKING_H__ */