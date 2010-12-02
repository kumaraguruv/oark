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

STATUS_t CheckVAD( HANDLE device, DWORD PID, PSLIST_HEADER * vad_usefull_head )
{
	char * eprocess = NULL;
	void * vad_root;
	READ_KERN_MEM_t read_kern_mem;
	STATUS_t returnf = ST_ERROR;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0; 
	DWORD dwVersion;
	BOOLEAN is_2k_xp;

	dwVersion = GetVersion();

	dwMajorVersion = (DWORD) ( LOBYTE( LOWORD( dwVersion ) ) );
	dwMinorVersion = (DWORD) ( HIBYTE( LOWORD( dwVersion ) ) );

	if ( dwMajorVersion == 5 )
		is_2k_xp = TRUE;
	else
		is_2k_xp = FALSE;


	* vad_usefull_head = (PSLIST_HEADER) _aligned_malloc( sizeof( ** vad_usefull_head ), MEMORY_ALLOCATION_ALIGNMENT );
	if( * vad_usefull_head != NULL )
	{
		if ( debug )
			printf( " OK: Init vad_usefull_head\n" );

		InitializeSListHead( * vad_usefull_head );

		PsLookupProcessByProcessId( device, PID, & eprocess );
		if ( eprocess != NULL )
		{
			if ( debug )
				printf( " EPROCESS: 0x%08X\n", eprocess );
			if ( is_2k_xp )
			{
				read_kern_mem.type        = SYM_TYP_NULL;
				read_kern_mem.dst_address = & vad_root;
				read_kern_mem.size        = sizeof( vad_root );
				read_kern_mem.src_address = ( eprocess + Offsets.VAD_ROOT );

				if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
					fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
				else
					_CheckVAD2KXP( device, vad_root, * vad_usefull_head, & returnf );
			}
			else
				_CheckVADVista7( device, eprocess + Offsets.VAD_ROOT, * vad_usefull_head, & returnf );

			ObDereferenceObject( device, eprocess );
		}

		if ( returnf != ST_OK )
			_aligned_free( * vad_usefull_head );
	}
	else
		fprintf( stderr, " Error: Init vad_usefull_head\n" );

	return returnf;
}

VOID _CheckVADVista7( HANDLE device, void * vad_node, PSLIST_HEADER vad_usefull_head, STATUS_t * returnf )
{
	ULONG starting_vpn = 0;
	ULONG ending_vpn = 0;
	READ_KERN_MEM_t read_kern_mem;
	CONTROL_AREA control_area;
	VAD_USEFULL_t * vad_usefull_entry;
	void * child;
	MMVAD_VISTA mmvad_rvad_node;
	SUBSECTION subsection;
	EX_FAST_REF file_pointer;                       

	read_kern_mem.type        = SYM_TYP_NULL;
	read_kern_mem.dst_address = & mmvad_rvad_node;
	read_kern_mem.size        = sizeof( mmvad_rvad_node );
	read_kern_mem.src_address = vad_node;

	if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
		fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
	else
	{
		child = mmvad_rvad_node.LeftChild;

		if ( child != NULL )
			_CheckVADVista7( device, child, vad_usefull_head, returnf );

		read_kern_mem.type        = SYM_TYP_NULL;
		read_kern_mem.dst_address = & subsection;
		read_kern_mem.size        = sizeof( subsection );
		read_kern_mem.src_address = mmvad_rvad_node.Subsection;

		if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
			fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
		else
		{
			if ( subsection.ControlArea != NULL )
			{
				if ( debug )
					printf
					( 
						" vad_node: 0x%08X\n"
						" ControlArea: 0x%08X\n"
						" Subsection: 0x%08X\n"
						, 
						vad_node,
						subsection.ControlArea,
						mmvad_rvad_node.Subsection
					);
				read_kern_mem.type        = SYM_TYP_NULL;
				read_kern_mem.dst_address = & control_area;
				read_kern_mem.size        = sizeof( control_area );
				read_kern_mem.src_address = subsection.ControlArea;

				if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
					fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
				else
				{
					vad_usefull_entry = (VAD_USEFULL_t *) _aligned_malloc \
						( sizeof(* vad_usefull_entry), MEMORY_ALLOCATION_ALIGNMENT ); 

					if( vad_usefull_entry == NULL )
						fprintf( stderr, " Error: Memory allocation failed.\n" );
					else
					{
						memset( vad_usefull_entry, 0, sizeof( * vad_usefull_entry ) );

						vad_usefull_entry->starting_vpn = mmvad_rvad_node.StartingVpn << 12;
						vad_usefull_entry->ending_vpn = ( mmvad_rvad_node.EndingVpn + 1 ) << 12; 

						InterlockedPushEntrySList
							( vad_usefull_head, &( vad_usefull_entry->SingleListEntry ) );

						* returnf = TRUE;
						if ( debug )
							printf
							( 
							" ------------------------\n"
							" StartingVpn: 0x%08X\n"
							" EndingVpn: 0x%08X\n"
							, 
							vad_usefull_entry->starting_vpn,
							vad_usefull_entry->ending_vpn
							); 

						if ( control_area.FilePointer != NULL )
						{
							printf( " FilePointer 0x%08X\n", control_area.FilePointer );  getchar();
							read_kern_mem.type        = SYM_TYP_NULL;
							read_kern_mem.dst_address = & file_pointer;
							read_kern_mem.size        = sizeof( file_pointer );
							read_kern_mem.src_address = control_area.FilePointer;

							if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
								fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
							else
							{
								if ( file_pointer.Object != NULL )
								{
									if ( file_pointer.Value > ( sizeof( vad_usefull_entry->dll_name ) - 2 ) )
										file_pointer.Value = ( sizeof( vad_usefull_entry->dll_name ) - 2 );
									if ( file_pointer.Value > 0 )
									{
										read_kern_mem.type        = SYM_TYP_NULL;
										read_kern_mem.dst_address = vad_usefull_entry->dll_name;
										read_kern_mem.size        = file_pointer.Value;
										read_kern_mem.src_address = file_pointer.Object;

										if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
											fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
										else
										{
											if ( debug )
												printf( " File Name: %S\n", vad_usefull_entry->dll_name );
										}
									}
								}
							}
						}
					}
				}
			}
		}

		child = mmvad_rvad_node.RightChild;

		if ( child != NULL )
			_CheckVADVista7( device, child, vad_usefull_head, returnf );
	}
}


VOID _CheckVAD2KXP( HANDLE device, void * vad_node, PSLIST_HEADER vad_usefull_head, STATUS_t * returnf )
{
	ULONG starting_vpn = 0;
	ULONG ending_vpn = 0;
	READ_KERN_MEM_t read_kern_mem;
	CONTROL_AREA control_area;
	UNICODE_STRING file_pointer;
	VAD_USEFULL_t * vad_usefull_entry;
	void * child;
	MMVAD_XP mmvad_rvad_node;

	read_kern_mem.type        = SYM_TYP_NULL;
	read_kern_mem.dst_address = & mmvad_rvad_node;
	read_kern_mem.size        = sizeof( mmvad_rvad_node );
	read_kern_mem.src_address = vad_node;

	if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
		fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
	else
	{
		child = mmvad_rvad_node.LeftChild;

		if ( child != NULL )
			_CheckVAD2KXP( device, child, vad_usefull_head, returnf );

		if ( mmvad_rvad_node.ControlArea != NULL )
		{
			read_kern_mem.type        = SYM_TYP_NULL;
			read_kern_mem.dst_address = & control_area;
			read_kern_mem.size        = sizeof( control_area );
			read_kern_mem.src_address = mmvad_rvad_node.ControlArea;

			if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
				fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
			else
			{
				vad_usefull_entry = (VAD_USEFULL_t *) _aligned_malloc \
					( sizeof(* vad_usefull_entry), MEMORY_ALLOCATION_ALIGNMENT ); 

				if( vad_usefull_entry == NULL )
					fprintf( stderr, " Error: Memory allocation failed.\n" );
				else
				{
					memset( vad_usefull_entry, 0, sizeof( * vad_usefull_entry ) );

					vad_usefull_entry->starting_vpn = mmvad_rvad_node.StartingVpn << 12;
					vad_usefull_entry->ending_vpn = ( mmvad_rvad_node.EndingVpn + 1 ) << 12; 

					InterlockedPushEntrySList
						( vad_usefull_head, &( vad_usefull_entry->SingleListEntry ) );

					* returnf = TRUE;
					if ( debug )
						printf
						( 
							" ------------------------\n"
							" StartingVpn: 0x%08X\n"
							" EndingVpn: 0x%08X\n"
							, 
							vad_usefull_entry->starting_vpn,
							vad_usefull_entry->ending_vpn
							); 

					if ( control_area.FilePointer != NULL )
					{
						read_kern_mem.type        = SYM_TYP_NULL;
						read_kern_mem.dst_address = & file_pointer;
						read_kern_mem.size        = sizeof( file_pointer );
						read_kern_mem.src_address = (char *) & ((PFILE_OBJECT) control_area.FilePointer)->FileName;

						if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
							fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
						else
						{
							if ( file_pointer.Buffer != NULL )
							{
								if ( file_pointer.Length > ( sizeof( vad_usefull_entry->dll_name ) - 2 ) )
									file_pointer.Length = ( sizeof( vad_usefull_entry->dll_name ) - 2 );
								if ( file_pointer.Length > 0 )
								{
									read_kern_mem.type        = SYM_TYP_NULL;
									read_kern_mem.dst_address = vad_usefull_entry->dll_name;
									read_kern_mem.size        = file_pointer.Length;
									read_kern_mem.src_address = file_pointer.Buffer;
								
									if ( IOCTLReadKernMem( device, & read_kern_mem ) == NULL )
										fprintf( stderr, " Error: IOCTL CHANGE MODE\n" );
									else
									{
										if ( debug )
											printf( " File Name: %S\n", vad_usefull_entry->dll_name ); 
									}
								}
							}
						}
					}
				}
			}
		}

		child = mmvad_rvad_node.RightChild;

		if ( child != NULL )
			_CheckVAD2KXP( device, child, vad_usefull_head, returnf );
	}
}

