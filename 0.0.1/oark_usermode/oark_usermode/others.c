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

#include "others.h"

STATUS_t LockInstance( DWORD * other_pid )
{
	char * file_path;
	STATUS_t returnf = ST_ERROR;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32, aux_pe32;

	if ( GetFullTempPath( & file_path, "oark_tmp_lck" ) )
	{
		if 
		(
			CreateFileA \
			( 
				file_path,
				GENERIC_READ | GENERIC_WRITE,
				0, 
				NULL,
				CREATE_ALWAYS,
				0,
				NULL
			)
			!=
			INVALID_HANDLE_VALUE
		)
			returnf = ST_OK;
		else
		{
			if ( debug )
				printf( " OK: lock file already locking: %s, checking if the process is already open..\n", file_path );

			hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
			if( hProcessSnap != INVALID_HANDLE_VALUE )
			{
				pe32.dwSize = sizeof( pe32 );

				if( Process32First( hProcessSnap, & pe32 ) )
				{
					do
					{
						if ( pe32.th32ProcessID == GetCurrentProcessId() )
						{
							if ( debug )
								printf
								( 
									" OK: Found own exe file: %S - PID: %d\n", pe32.szExeFile, pe32.th32ProcessID 
								);

							break;
						}

					  } while( Process32Next( hProcessSnap, & pe32 ) );

					  CloseHandle( hProcessSnap );
				}

				hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
				if( hProcessSnap != INVALID_HANDLE_VALUE )
				{
					aux_pe32.dwSize = sizeof( aux_pe32 );

					if( Process32First( hProcessSnap, & aux_pe32 ) )
					{
						returnf = ST_OK;
						do
						{
							if ( pe32.th32ProcessID != aux_pe32.th32ProcessID )
							{
								if ( lstrcmpW( pe32.szExeFile, aux_pe32.szExeFile ) == 0 )
								{
									if ( debug )
										printf
										( 
											" OK: Found other exe file with the same name: %S - PID: %d\n", 
											aux_pe32.szExeFile,
											aux_pe32.th32ProcessID
										);
									if ( other_pid != NULL )
										* other_pid = aux_pe32.th32ProcessID;

									returnf = ST_ERROR;

									break;
								}
							}

						  } while( Process32Next( hProcessSnap, & aux_pe32 ) );

						  CloseHandle( hProcessSnap );
					}
				}

			}
		}

		free( file_path );
	}

	return returnf;
}

BOOLEAN GetFullTempPath( char ** out_full_temp_path, char * name )
{  
    char full_temp_path[MAX_PATH];
	DWORD ret_val = 0;

	ret_val = GetTempPathA( MAX_PATH, full_temp_path ); 
    if ( ret_val > MAX_PATH || ( ret_val == 0 ) )
		return FALSE;
    
	if 
	( 
		( strlen( full_temp_path ) + strlen( name ) ) 
		>=
		sizeof( full_temp_path ) 
	)
		return FALSE;

	* out_full_temp_path = calloc( 1, sizeof( full_temp_path ) );
	if ( * out_full_temp_path == NULL )
		return FALSE;

	strcat( full_temp_path, name );

	memcpy( * out_full_temp_path, full_temp_path, sizeof( full_temp_path ) );

	return TRUE;
}

BOOLEAN DumpRSRC( char * full_temp_path, int resource_id, char * driver_name )
{
	HRSRC handle_rsrc;
	HGLOBAL handle_rsrc_load;
	PVOID rsrc_lock;
	DWORD size_of_rsrc;
	FILE * file;
	BOOLEAN returnf = FALSE;

	handle_rsrc = FindResourceA( NULL, MAKEINTRESOURCEA( resource_id ), driver_name );
	if ( handle_rsrc != NULL )
	{
		if ( debug )
			printf( " OK: Finding RSRC\n" );

		handle_rsrc_load = LoadResource( NULL, handle_rsrc );

		if ( handle_rsrc_load != NULL )
		{
			if ( debug )
				printf( " OK: Loading RSRC\n" );

			rsrc_lock = LockResource( handle_rsrc_load );
			if ( rsrc_lock != NULL )
			{
				if ( debug )
					printf( " OK: Get size of RSRC\n" );

				size_of_rsrc = SizeofResource( NULL, handle_rsrc );
				if ( size_of_rsrc != 0 )
				{
					file = fopen( full_temp_path, "wb" );
					if ( file != NULL )
					{
						if ( debug )
							printf( " OK: Open the file to dump: %s\n", full_temp_path );

						if ( fwrite( rsrc_lock, size_of_rsrc, 1, file ) == 1 )
						{
							if ( debug )
								printf( " OK: Dumping the data\n" );

							returnf = TRUE;
						}
						else
							fprintf( stderr, " Error: Dumping the data\n" );

						fclose( file );
					}
					else
					{
						fprintf( stderr, " Error: Open the file to dump: %s\n", full_temp_path );
						perror( "" );
					}
				}
			}
			else
				fprintf( stderr, " Error: Get size of RSRC\n" );
		}
		else
			fprintf( stderr, " Error: Loading RSRC\n" );
	}
	else
		fprintf( stderr, " Error: Finding RSRC\n" );

	return returnf;
}

STATUS_t Init( void )
{
	ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS_t) \
		GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "ZwQueryInformationProcess" );

	if ( ZwQueryInformationProcess == NULL )
	{
		fprintf( stderr, " Error: Getting ZwQueryInformationProcess from ntdll\n" );
		return ST_ERROR;
	}
	else
	{
		if ( debug )
			printf( " OK: Getting ZwQueryInformationProcess from ntdll\n" );
		return ST_OK;
	}
};

void CheckOSVersion( void )
{
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0; 
	DWORD dwVersion;

	if ( debug )
		printf( " INFO: Checking version\n" );

	Offsets.isSupported = TRUE;

	dwVersion = GetVersion();

	dwMajorVersion = (DWORD) ( LOBYTE( LOWORD( dwVersion ) ) );
	dwMinorVersion = (DWORD) ( HIBYTE( LOWORD( dwVersion ) ) );

	if ( debug )
		printf( " OK: dwMajorVersion: %d dwMinorVersion: %d\n", dwMajorVersion, dwMinorVersion );

	switch ( dwMajorVersion )
	{
		case 5:
			if ( debug )
				printf( " INFO: OS=2000, XP, Server 2003\n" );

			Offsets.VAD_FILE_POINTER = 0x30;
			Offsets.VAD_ROOT = 0x11c;
		break;

		case 6:
			switch ( dwMinorVersion )
			{
				case 0:
					if ( debug )
						printf( " INFO: OS=Vista, Server 2008\n" );

					Offsets.VAD_FILE_POINTER = 0x30;
					Offsets.VAD_ROOT = 0x11c;
				break;

				case 1:
					if ( debug )
						printf( " INFO: OS=7\n" );
					
					Offsets.VAD_FILE_POINTER = 0x30;
					Offsets.VAD_ROOT = 0x11c;
				break;

				default:
					fprintf( stderr, " Error: KERNEL MINOR NOT SUPPORTED, DKOM DISABLE, USING STANDARD WAYS...\n" );
					Offsets.isSupported = FALSE;
				break;
			}
			break;

		default:
			fprintf( stderr, " Error: KERNEL MINOR NOT SUPPORTED, DKOM DISABLE, USING STANDARD WAYS...\n" );
			Offsets.isSupported = FALSE;
		break;
	}

	if ( Offsets.isSupported )
	{
		if ( debug )
			printf( " OK: VAD ROOT: 0x%X\n", Offsets.VAD_ROOT );
	}
}
