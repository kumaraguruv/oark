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

#ifndef _VAD_H__
#define _VAD_H__

#include <Windows.h>
#include "others.h"
#include "driverusr.h"

typedef struct _CONTROL_AREA
{
	struct _SEGMENT* Segment;
	LIST_ENTRY DereferenceList;
	UINT32 NumberOfSectionReferences;
	UINT32 NumberOfPfnReferences;
	UINT32 NumberOfMappedViews;
	UINT16 NumberOfSubsections;
	UINT16 FlushInProgressCount;
	UINT32 NumberOfUserReferences;
	UINT32 u;
	PVOID FilePointer; /* PFILE_OBJECT FilePointer; */
	struct _EVENT_COUNTER* WaitingForDeletion;
	UINT16 ModifiedWriteCount;
	UINT16 NumberOfSystemCacheViews;
} CONTROL_AREA, *PCONTROL_AREA;

typedef struct _MMVAD
{
	UINT32 StartingVpn;
	UINT32 EndingVpn;
	struct _MMVAD* Parent;
	struct _MMVAD* LeftChild;
	struct _MMVAD* RightChild;
	ULONG32 u;
	PCONTROL_AREA ControlArea;
	struct _MMPTE* FirstPrototypePte;
	struct _MMPTE* LastContiguousPte;
	ULONG32 u2;
} MMVAD, *PMMVAD;

VOID CheckVAD( HANDLE, DWORD );
VOID _CheckVAD( HANDLE, PMMVAD );



#endif /* _VAD_H__ */
