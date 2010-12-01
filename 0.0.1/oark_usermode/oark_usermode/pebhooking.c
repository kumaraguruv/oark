/*
" - This POC DETECTS PEB HOOKING via:\n"
" - Different DLL Name of the FULL PATH NAME (string inside).\n"
" - Same DLL Name in two or more PEB entries.\n"
" - Same DLL FULL Name PATH in two or more PEB entries.\n"
" - Different SIZE OF IMAGE PEB data and PE32 RAW DISK FILE DATA.\n"
" - Different ENTRY POINT PEB data and PE32 RAW DISK FILE DATA. Except NTDLL ofc\n"
" - Different TIME DATE STAMP PEB data and PE32 RAW DISK FILE DATA.\n"
" - \n"
" - For the arks:\n"
" - The best way is dump phys memory without APIs like ReadProcessMemory\n"
" - Get PEB ADDRESS from lowlevel (without ZwQueryInformationProcess/ReadProcc..\n"
" - Read the raw disk from OWN NTFS driver parser wihout APIs..\n"
" - This POC ASSUMES you know get the HIDDEN DLLS FROM PEB WITH VAD WALK..\n"
" - (I mean, If there are hidden dlls it is irrelevant if exist peb hooking)...\n"
" - Also ASSUMES you have other code which check the other DLL Lists of the PEB..\n"

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

#include "pebhooking.h"


STATUS_t CheckPEBHooking( HANDLE device )
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD own_pid;

	own_pid = GetCurrentProcessId();

	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap != INVALID_HANDLE_VALUE )
	{
		pe32.dwSize = sizeof( pe32 );

		if( Process32First( hProcessSnap, & pe32 ) )
		{
			do 
			{
				if ( pe32.th32ProcessID != own_pid )
				{
					if ( _CheckPEBHooking( device, pe32.th32ProcessID ) == -1 )
						fprintf( stderr, " Error: Checking PEB HOOKING PID :%d\n", pe32.th32ProcessID );
				}

			} while( Process32Next( hProcessSnap, & pe32 ) );

			CloseHandle( hProcessSnap );
		}
	}


	return ST_OK;
}

int _CheckPEBHooking( HANDLE device, DWORD PID )
{
	HANDLE hProcess;
	int returnf = -1;
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb;
	DWORD lpNumberOfBytesRead;
	PEB_LDR_DATA LoaderData;
	PLDR_MODULE pfirst_ldr_module;
	LDR_MODULE  ldr_module;
	PLDR_MODULE pactual_ldr_module;
	char full_dll_name[(MAX_PATH * 2) + 2];
	char base_dll_name[(MAX_PATH * 2) + 2];
	int i = 0;
	PSLIST_HEADER ldr_usefull_head;
	LDR_USEFULL_t * ldr_usefull_entry;
	char * aux;
	PSLIST_HEADER vad_usefull_head;

	ldr_usefull_head = (PSLIST_HEADER) _aligned_malloc( sizeof( * ldr_usefull_head ), MEMORY_ALLOCATION_ALIGNMENT );
	if( ldr_usefull_head != NULL )
	{
		InitializeSListHead( ldr_usefull_head );

		if ( debug )
			printf( " OK: Detecting PEB HOOKING in PID: %d\n", PID );

		hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, PID );
		if( hProcess == NULL )
			fprintf( stderr, "Error: OpenProcess PROCESS_VM_READ | PROCESS_QUERY_INFORMATION\n" );
		else
		{
			if ( ZwQueryInformationProcess
				( 
				hProcess, 
				ProcessBasicInformation, 
				(PVOID) & pbi, 
				sizeof(PROCESS_BASIC_INFORMATION), 
				NULL 
				) != STATUS_SUCCESS )
			{
				fprintf( stderr, " Error: calling ZwQueryInformationProcess PROCESS_BASIC_INFORMATION.\n" );
			}
			else
			{
				if ( debug )
				{
					printf( " OK: calling ZwQueryInformationProcess PROCESS_BASIC_INFORMATION.\n" );
					printf( " PebBaseAddress: 0x%08X\n", pbi.PebBaseAddress );
				}

				if ( ReadProcessMemory
					( 
					hProcess, 
					(void*) pbi.PebBaseAddress, 
					(void*) & peb, 
					sizeof( peb ), 
					& lpNumberOfBytesRead
					) == 0 )  
				{
					fprintf( stderr, " Error: reading remote PEB." );
					fprintf( stderr, " Read only: %d bytes.\n", lpNumberOfBytesRead );
				}
				else
				{
					if ( debug )
					{
						printf( " OK: reading remote PEB.\n" );

						printf( " InheritedAddressSpace   : 0x%02X\n", peb.InheritedAddressSpace );
						printf
							( 
							" ReadImageFileExecOptions: 0x%02X\n", 
							peb.ReadImageFileExecOptions 
							);
						printf( " BeingDebugged           : 0x%02X\n",   peb.BeingDebugged );
						printf( " Spare                   : 0x%02X\n",   peb.Spare );
						printf( " Mutant                  : 0x%08X\n",   peb.Mutant );
						printf( " ImageBaseAddress        : 0x%08X\n", peb.ImageBaseAddress );
						printf( " LoaderData              : 0x%08X\n", peb.LoaderData );
					}

					if ( ReadProcessMemory
						( 
						hProcess, 
						(void*) peb.LoaderData, 
						(void*) & LoaderData, 
						sizeof(LoaderData), 
						&lpNumberOfBytesRead
						) == 0 )  
					{
						fprintf( stderr, " Error: reading remote LoaderData" );
						fprintf( stderr, " Only read: %d bytes.\n", lpNumberOfBytesRead );
					}
					else
					{
						if ( debug )
						{
							printf( " OK: reading remote LoaderData.\n" );

							printf( " Length                         : 0x%08X\n", LoaderData.Length );
							printf( " Initialized                    : 0x%02X\n", LoaderData.Initialized );
							printf( " SsHandle                       : 0x%08X\n", LoaderData.SsHandle );
							printf( " InLoadOrderModuleList          : Flink 0x%08X - Blink 0x%08X\n", LoaderData.InLoadOrderModuleList.Flink, LoaderData.InLoadOrderModuleList.Blink );
							printf( " InMemoryOrderModuleList        : Flink 0x%08X - Blink 0x%08X\n", LoaderData.InMemoryOrderModuleList.Flink, LoaderData.InMemoryOrderModuleList.Blink );
							printf( " InInitializationOrderModuleList: Flink 0x%08X - Blink 0x%08X\n", LoaderData.InInitializationOrderModuleList.Flink, LoaderData.InInitializationOrderModuleList.Blink );
						}

						pactual_ldr_module = (PLDR_MODULE) LoaderData.InLoadOrderModuleList.Flink;
						i = 0;
						do
						{
							if ( ReadProcessMemory
								( 
								hProcess, 
								(void*) pactual_ldr_module,
								(void*) & ldr_module, 
								sizeof(ldr_module), 
								&lpNumberOfBytesRead
								) == 0 )  
							{
								fprintf( stderr, " Error: reading remote \"LDR MODULE\".\n" );
								fprintf( stderr, " Only Read: %d bytes.\n", lpNumberOfBytesRead );
							}
							else
							{
								if ( i == 0 )
									pfirst_ldr_module = (PLDR_MODULE) ldr_module.InLoadOrderModuleList.Blink;

								if ( debug )
								{
									printf( " OK: reading remote \"LDR MODULE\".\n" );
									printf( " InLoadOrderModuleList          : Flink 0x%08X - Blink 0x%08X\n", ldr_module.InLoadOrderModuleList.Flink, ldr_module.InLoadOrderModuleList.Blink );
									printf( " InMemoryOrderModuleList        : Flink 0x%08X - Blink 0x%08X\n", ldr_module.InMemoryOrderModuleList.Flink, ldr_module.InMemoryOrderModuleList.Blink );
									printf( " InInitializationOrderModuleList: Flink 0x%08X - Blink 0x%08X\n", ldr_module.InInitializationOrderModuleList.Flink, ldr_module.InInitializationOrderModuleList.Blink );
									printf( "                     BaseAddress: 0x%08X\n", ldr_module.BaseAddress );
									printf( "                      EntryPoint: 0x%08X\n", ldr_module.EntryPoint );
									printf( "                     SizeOfImage: 0x%08X\n", ldr_module.SizeOfImage );

									printf( "                     FullDllName: 0x%08X\n", ldr_module.FullDllName.Buffer );
									printf( "                     BaseDllName: 0x%08X\n", ldr_module.BaseDllName.Buffer );
									printf( "                           Flags: 0x%08X\n", ldr_module.Flags );
									printf( "                       LoadCount: 0x%08X\n", ldr_module.LoadCount );
									printf( "                        TlsIndex: 0x%08X\n", ldr_module.TlsIndex );
									printf( "                  HashTableEntry: 0x%08X\n", ldr_module.HashTableEntry );

									printf( "                   TimeDateStamp: 0x%08X\n", ldr_module.TimeDateStamp );
								}

								memset( base_dll_name, 0, sizeof( base_dll_name ) );

								if ( ReadProcessMemory
									( 
									hProcess, 
									(void*) ldr_module.BaseDllName.Buffer,
									(void*) base_dll_name, 
									sizeof(base_dll_name) - 2, 
									& lpNumberOfBytesRead
									) == 0 )  
								{
									fprintf( stderr, " Error: reading remote \"base_dll_name\".\n" );
									fprintf( stderr, " Only Read: %d bytes.\n", lpNumberOfBytesRead );
								}
								else
								{
									if ( debug )
										printf( " OK: reading remote \"base_dll_name\": %S\n", base_dll_name );
								}

								memset( full_dll_name, 0, sizeof( full_dll_name ) );
								if ( ReadProcessMemory
									( 
									hProcess, 
									(void*) ldr_module.FullDllName.Buffer,
									(void*) full_dll_name, 
									sizeof(full_dll_name) - 2, 
									& lpNumberOfBytesRead
									) == 0 )  
								{
									fprintf( stderr, " Error: reading remote \"base_dll_name\".\n" );
									fprintf( stderr, " Only Read: %d bytes.\n", lpNumberOfBytesRead );
								}
								else
								{
									if ( debug )
										printf( " OK: reading remote \"full_dll_name\": %S\n", full_dll_name );

									ldr_usefull_entry = (LDR_USEFULL_t *) _aligned_malloc \
										( sizeof(* ldr_usefull_entry), MEMORY_ALLOCATION_ALIGNMENT ); 

									if( ldr_usefull_entry == NULL )
										fprintf( stderr, " Error: Memory allocation failed.\n" );
									else
									{
										memset( ldr_usefull_entry, 0, sizeof( * ldr_usefull_entry ) );

										memcpy( ldr_usefull_entry->base_dll_name, base_dll_name, 
											sizeof( base_dll_name ) );
										memcpy( ldr_usefull_entry->full_dll_name, full_dll_name, 
											sizeof( full_dll_name ) );
										ldr_usefull_entry->size_of_image = ldr_module.SizeOfImage;
										ldr_usefull_entry->time_data_stamp = ldr_module.TimeDateStamp;
										ldr_usefull_entry->base_address = (DWORD) ldr_module.BaseAddress;
										ldr_usefull_entry->ep_without_ba = ( (DWORD) ldr_module.EntryPoint );
										if ( ldr_usefull_entry->ep_without_ba != 0 )
											ldr_usefull_entry->ep_without_ba -= ldr_usefull_entry->base_address;

										InterlockedPushEntrySList
											( ldr_usefull_head, &( ldr_usefull_entry->SingleListEntry ) );

										returnf = 0;
									}

								}
							}

							pactual_ldr_module = (PLDR_MODULE) ldr_module.InLoadOrderModuleList.Flink;
							i++;
						} while ( pactual_ldr_module != pfirst_ldr_module );						
					} 
				}
			}

			if ( returnf == 0 )
			{
				if ( debug )
					puts( "\n" );
				ldr_usefull_entry = (LDR_USEFULL_t *) ldr_usefull_head->Next.Next;
				if ( debug )
					printf( " -------------------------------\n" );

				if ( debug )
					printf( "\n Getting VADs:..\n" );

				CheckVAD( device, PID, & vad_usefull_head );

				while ( ldr_usefull_entry != NULL )
				{

					if ( debug )
						printf( " Compare PEB entry Info with VAD entry Info...\n" );

					ComparePEBEntryVADInfo( ldr_usefull_entry, vad_usefull_head );

					if ( debug )
					{
						printf
							( 
							" Checking FULL PATH: %S\n"
							" DLL: %S\n\n", 
							ldr_usefull_entry->full_dll_name,
							ldr_usefull_entry->base_dll_name
							);
					}

					if ( debug )
						printf( " Checking Duplicate entries in the PEB for this entry (same dll name / full)...\n" );

					CheckDuplicateEntries( ldr_usefull_head, ldr_usefull_entry );

					aux = \
						ldr_usefull_entry->full_dll_name 
						+ 
						( lstrlenW( (LPCWSTR) ldr_usefull_entry->full_dll_name ) * 2 );

					if ( debug )
						printf( " Searching incogruency from the dll path and full dll patch fields...\n" );
					while ( aux >= ldr_usefull_entry->full_dll_name )
					{
						if ( strcmp( aux, "\\" ) == 0 )
						{
							if ( lstrcmpW( (LPCWSTR) (aux + 2), (LPCWSTR) ldr_usefull_entry->base_dll_name ) == 0 )
							{
								if ( debug )
									printf( " OK!, dll name of full path is the same of the dll name: %S\n", aux + 2 );
								break;
							}
							else
							{
								printf
									( 
									" DLL NAME OF FULL PATH DIFFERENT OF THE DLL NAME!, MAYBE PEB HOOKING: %S\n", 
									aux + 2 
									);
								break;
							}
						}
						aux -= 2;
					}

					if ( debug )
						printf( "\n Checking raw file in disk (for arks the best way with driver parsing ntfs..):\n" );
					CheckRawFile( ldr_usefull_entry );


					if ( debug ) 
						printf( " -------------------------------\n" );

					ldr_usefull_entry = (LDR_USEFULL_t *) ldr_usefull_entry->SingleListEntry.Next;

				}
			}

			CloseHandle( hProcess );
		}
	}
	else
		fprintf( stderr, " Error: Memory allocation failed.\n" );

	return returnf;
}

void CheckRawFile( LDR_USEFULL_t * ldr_usefull_entry )
{
	FILE * file;
	IMAGE_DOS_HEADER image_dos_header;
	IMAGE_NT_HEADERS image_nt_headers;

	file = _wfopen( (wchar_t *) ldr_usefull_entry->full_dll_name, L"rb" );

	if ( file == NULL )
	{
		fprintf( stderr, " Error: opening file: %S\n", ldr_usefull_entry->full_dll_name );
		perror( "" );
		return;
	}

	if ( debug )
		printf( " OK, Open!: %S\n", ldr_usefull_entry->full_dll_name );

	fseek( file, 0L, 0L );

	if ( fread( & image_dos_header, sizeof( image_dos_header ), 1, file ) == 1 )
	{
		fseek( file, image_dos_header.e_lfanew, 0L );

		if ( fread( & image_nt_headers, sizeof( image_nt_headers ), 1, file ) == 1 )
		{
			if ( debug )
				printf( " ImageBase FILE 0x%08X\n", image_nt_headers.OptionalHeader.ImageBase );

			if ( debug )
				printf( " Entry Point FILE 0x%08X\n", image_nt_headers.OptionalHeader.AddressOfEntryPoint );

			if ( ldr_usefull_entry->ep_without_ba != image_nt_headers.OptionalHeader.AddressOfEntryPoint )
				printf( " MAYBE PEB HOOKING!! RAW FILE ENTRY POINT DIFFERENT FROM PEB ENTRY POINT\n" );
			else
			{
				if ( debug )
					printf( " OK! entry point is the same of the file\n" );
			}

			if ( ldr_usefull_entry->size_of_image != image_nt_headers.OptionalHeader.SizeOfImage )
				printf( " MAYBE PEB HOOKING!! RAW FILE SIZE OF IMAGE DIFFERENT FROM PEB SIZE OF IMAGE\n" );
			else
			{
				if ( debug )
					printf( " OK!, size of image is the same\n" );
			}

			if ( ldr_usefull_entry->time_data_stamp != image_nt_headers.FileHeader.TimeDateStamp )
				printf( " MAYBE PEB HOOKING!! RAW FILE TIME DATA STAMP DIFFERENT FROM PEB TIME DATE STAMP\n" );
			else
			{
				if ( debug )
					printf( " OK!, time data stamp is the same\n" );
			}
		}
		else
			fprintf( stderr, " Error: Reading IMAGE NT HEADERS\n" );
	}
	else
		fprintf( stderr, " Error: Reading IMAGE DOS HEADER\n" );

	fclose( file );
}

void CheckDuplicateEntries( PSLIST_HEADER ldr_usefull_head, LDR_USEFULL_t * in_ldr_usefull_entry )
{
	LDR_USEFULL_t * ldr_usefull_entry;

	ldr_usefull_entry = (LDR_USEFULL_t *) ldr_usefull_head->Next.Next;
	while ( ldr_usefull_entry != NULL )
	{
		if ( ldr_usefull_entry != in_ldr_usefull_entry )
		{
			if 
				( 
				memcmp
				( 
				in_ldr_usefull_entry->base_dll_name, 
				ldr_usefull_entry->base_dll_name, 
				sizeof( in_ldr_usefull_entry->base_dll_name ) 
				) 
				== 
				0 
				)
			{
				printf( " MAYBE PEB HOOKING, THE SAME DLL NAME IN OTHER ENTRY!\n" );
			}

			if 
				( 
				memcmp
				( 
				in_ldr_usefull_entry->full_dll_name, 
				ldr_usefull_entry->full_dll_name, 
				sizeof( in_ldr_usefull_entry->full_dll_name ) 
				) 
				== 
				0 
				)
			{
				printf( " MAYBE PEB HOOKING, THE SAME FULL DLL NAME PATH IN OTHER ENTRY!\n" );
			}
		}

		ldr_usefull_entry = (LDR_USEFULL_t *) ldr_usefull_entry->SingleListEntry.Next;		
	}
}

void ComparePEBEntryVADInfo( LDR_USEFULL_t * ldr_usefull_entry, PSLIST_HEADER vad_usefull_head )
{
	VAD_USEFULL_t * vad_usefull_entry;
	BOOLEAN found = FALSE;

	vad_usefull_entry = (VAD_USEFULL_t *) vad_usefull_head->Next.Next;

	if ( debug )
		printf
		( 
		" Compare PEB entry Info with VAD entry Info...: %S - 0x%08X\n", 
		ldr_usefull_entry->base_dll_name, ldr_usefull_entry->base_address 
		);

	while ( vad_usefull_entry != NULL )
	{
		if ( ldr_usefull_entry->base_address == vad_usefull_entry->starting_vpn )
		{
			found = TRUE;
			break;
		}

		vad_usefull_entry = (VAD_USEFULL_t *) vad_usefull_entry->SingleListEntry.Next;
	}

	if ( found == TRUE )
	{
		if ( IsVADStringEqPebStr( vad_usefull_entry->dll_name, ldr_usefull_entry->full_dll_name ) == FALSE )
			printf( " MAYBE PEB HOOKING! VAD MEMORY FULL PATH DIFFERENT OF PEB ENTRY PATH\n" );
	}
	else
		printf( " MAYBE PEB HOOKING ONLY HIDDEN WITH VAD!\n" );
}

BOOLEAN IsVADStringEqPebStr( char * vad_name, char * peb_name )
{
	char peb_converted[(MAX_PATH * 2) + 2];
	char * aux = NULL;
	int i, j;
	BOOLAN found = FALSE;

	if ( debug )
		printf
		( 
			" --------\n"
			" VAD NAME: %S\n"
			" PEB NAME: %S\n"
			,
			vad_name,
			peb_name
		);

	/* THE BIG CRAP CODE IN THE WORLD!, COPY MY CODE IF YOU WANT! xD */

	if ( lstrlenW( peb_name ) >= ( strlen("\\??\\") * 2 ) + 2 )
	{
		i = 0;
		if ( peb_name[i] == '\\' )
		{
			i += 2;
			if ( peb_name[i] =='?' )
			{
				i += 2;
				if ( peb_name[i] =='?' )
				{
					i += 2;
					if ( peb_name[i] =='\\' )
					{
						i += 2;
						peb_name = & peb_name[i];
					}
				}
			}
		}
	}

	if ( lstrlenW( peb_name ) >= ( strlen("\\SystemRoot\\") * 2 ) + 2 )
	{
		i = 0;
		if ( peb_name[i] == '\\' )
		{
			i += 2;
			if ( peb_name[i] == 'S' )
			{
				i += 2;
				if ( peb_name[i] =='y' )
				{
					i += 2;
					if ( peb_name[i] =='s' )
					{
						i += 2;
						if ( peb_name[i] =='t' )
						{
							i += 2;
							if ( peb_name[i] =='e' )
							{
								i += 2;
								if ( peb_name[i] =='m' )
								{
									i += 2;
									if ( peb_name[i] =='R' )
									{
										i += 2;
										if ( peb_name[i] =='o' )
										{
											i += 2;
											if ( peb_name[i] =='o' )
											{
												i += 2;
												if ( peb_name[i] =='t' )
												{
													i += 2;
													if ( peb_name[i] =='\\' )
													{
														
														if ( getenv( "SystemRoot" ) != NULL )
														{
															printf( " SystemRoot!: %s\n", getenv( "SystemRoot" )  );
															aux = calloc( 1, (MAX_PATH * 2) + 2 );
															if ( aux != NULL )
															{
																for 
																( 
																	i = 0, j = 0; 
																	i < ( strlen( getenv( "SystemRoot" )  ) * 2 );
																	i += 2, j++
																)
																{
																	aux[i] = getenv( "SystemRoot" )[j];
																}

																memcpy
																( 
																	& aux[i], 
																	& peb_name[(strlen( "\\SystemRoot\\" ) * 2  ) - 2],
																	(
																		( 
																			( 
																				(lstrlenW( peb_name ) * 2) 
																				- 
																				( strlen( "\\SystemRoot\\" ) * 2 )
																			)
																			+ 
																			2
																		)
																	)
																);

																printf( " AUX: %S\n", aux );
																peb_name = aux;
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	for ( i = 0; i < (lstrlenW( peb_name ) * 2); i += 2 )
	{
		if ( peb_name[i] == '\\' )
		{
			lstrcpyW( peb_converted, & peb_name[i] );
			printf( " PEB CONVERTED: %S\n", peb_converted );

			if ( lstrcmpiW( peb_converted, vad_name ) == 0 )
				found = TRUE;
			break;
		}

	}
 
	if ( aux != NULL )
		free( aux );

	getchar();

	return found;
}