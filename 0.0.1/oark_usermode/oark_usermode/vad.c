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

#include "vad.h"

VOID PsLookupProcessByProcessId( HANDLE device, DWORD PID, char ** eprocess )
{
	READ_KERN_MEM_t read_kern_mem;

	read_kern_mem.type        = SYM_TYP_PSLOUPRBYID;
	read_kern_mem.src_address = (void *) PID;
	read_kern_mem.dst_address = eprocess;
	read_kern_mem.size        = sizeof( eprocess );

	if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
		fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
}

VOID ObDereferenceObject( HANDLE device, char * eprocess )
{
	READ_KERN_MEM_t read_kern_mem;

	read_kern_mem.type        = SYM_TYP_OBDEREFOBJ;
	read_kern_mem.src_address = (void *) eprocess;
	read_kern_mem.dst_address = NULL;
	read_kern_mem.size        = 0;

	IOCTLReadKernMem( device, & read_kern_mem );
}

VOID CheckVAD( HANDLE device, DWORD PID )
{
	char * eprocess = NULL;
	PMMVAD vad_root;
	READ_KERN_MEM_t read_kern_mem;

	PsLookupProcessByProcessId( device, PID, & eprocess );
	if ( eprocess != NULL )
	{
		read_kern_mem.type        = SYM_TYP_NULL;
		read_kern_mem.dst_address = & vad_root;
		read_kern_mem.size        = sizeof( vad_root );
		read_kern_mem.src_address = ( eprocess + Offsets.VAD_ROOT );

		if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
			fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
		else
			_CheckVAD( device, vad_root );

		ObDereferenceObject( device, eprocess );
	}
}


VOID _CheckVAD( HANDLE device, PMMVAD vad_node )
{
	ULONG starting_vpn = 0;
	ULONG ending_vpn = 0;
	MMVAD rvad_node;
	READ_KERN_MEM_t read_kern_mem;
	char dll_name[(MAX_PATH * 2) + 2];
	CONTROL_AREA control_area;
	UNICODE_STRING file_pointer;

	read_kern_mem.type        = SYM_TYP_NULL;
	read_kern_mem.dst_address = & rvad_node;
	read_kern_mem.size        = sizeof( rvad_node );
	read_kern_mem.src_address = vad_node;

	if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
		fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
	else
	{
		if ( rvad_node.LeftChild != NULL )
			_CheckVAD( device, rvad_node.LeftChild );

		if ( rvad_node.ControlArea != NULL )
		{
			read_kern_mem.type        = SYM_TYP_NULL;
			read_kern_mem.dst_address = & control_area;
			read_kern_mem.size        = sizeof( control_area );
			read_kern_mem.src_address = rvad_node.ControlArea;

			if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
				fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
			else
			{
				if ( control_area.FilePointer != NULL )
				{
					read_kern_mem.type        = SYM_TYP_NULL;
					read_kern_mem.dst_address = & file_pointer;
					read_kern_mem.size        = sizeof( file_pointer );
					read_kern_mem.src_address = ( (char *) control_area.FilePointer ) + Offsets.VAD_FILE_POINTER;

					if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
						fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
					else
					{
						if ( file_pointer.Buffer != NULL )
						{
							memset( dll_name, 0, sizeof( dll_name ) );

							if ( file_pointer.Length > ( sizeof( dll_name ) - 2 ) )
								file_pointer.Length = ( sizeof( dll_name ) - 2 );
							read_kern_mem.type        = SYM_TYP_NULL;
							read_kern_mem.dst_address = dll_name;
							read_kern_mem.size        = file_pointer.Length;
							read_kern_mem.src_address = file_pointer.Buffer;
						}

						if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
							fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
						else
						{
							rvad_node.StartingVpn <<=  12;
							rvad_node.EndingVpn <<= 12;
							if ( debug )
								printf
								( 
									" -----------------------\n"
									" File Name: %S\n" 
									" starting_vpn: 0x%08x\n"
									" ending_vpn: 0x%08x\n"
									,
									dll_name, 
									rvad_node.StartingVpn , 
									rvad_node.EndingVpn 
								);
						}
					}
				}
			}
		}

		if ( rvad_node.RightChild != NULL )
			_CheckVAD( device, rvad_node.RightChild );
	}
}

