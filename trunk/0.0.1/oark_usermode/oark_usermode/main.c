/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>
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

#include <stdio.h>
#include <windows.h>
#include "debug.h"
#include "common.h"
#include "driverusr.h"
#include "idt.h"
#include "ssdt.h"
#include "others.h"
#include "pebhooking.h"
#include "report.h"
#include "init.h"

int main( void )
{
	HANDLE device;
	DWORD other_pid;

	printf
	( 
		"\n"
		" +-----------------------------------------------------------------+\n"
		" | oark - The Open Source Anti Rootkit v%s                      |\n"
		" | MIT License - http://code.google.com/p/oark/                    |\n"
		" |                                                                 |\n"  
		" | Main Developers (Alphabetical order):                           |\n"
		" |   - Dreg aka David Reguera Garcia - Dreg@fr33project.org        |\n"
        " |   - 0vercl0k aka Axel Souchet - 0vercl0k@tuxfamily.org          |\n"
		" |                                                                 |\n"
		" | Committers (Alphabetical order):                                |\n"
		" |                                                                 |\n"
		" | Credits / Greetings (Alphabetical order):                       |\n"
		" |   - EP_X0FF aka DiabloNova (Rootkit Unhooker inspiration)       |\n" 
		" +-----------------------------------------------------------------+\n"
		"\n"
		, 
		OARK_VERSION 
	);

	if ( LockInstance( & other_pid ) == ST_OK )
	{
		if ( debug )
			printf( " ON: Only this instance running\n" );

		if ( EnableDebugPrivilege() == ST_ERROR )
			fprintf( stderr, " Error: EnableDebugPrivilege\n" );
		else
		{
			if ( debug )
				printf( " OK: EnableDebugPrivilege\n" );

			if ( Init() == ST_OK )
			{
				if ( debug )
					printf( " OK: Init\n" );

				if ( LoadDriver( & device ) )
				{
					if ( debug )
						printf( " OK: Driver Loaded!\n" );

					CheckOSVersion();
                    
                    RenderInitialization();

                    InitCalls( device );
 
                    printf(" Generation of the report..");
                    MakeReport(OUTPUT_FORMAT_TXT, OUTPUT_DST_STDOUT, FALSE );
                    printf(" Generation of the file report..");
                    MakeReport(OUTPUT_FORMAT_TXT, OUTPUT_DST_FILE, TRUE );
                    printf("OK\n Check %s file !\n", OARK_FILENAME_LOG);

					if ( UnloadDriver( & device ) )
					{
						if ( debug ) 
							printf( " OK: Driver Unloaded!\n" );
					}
					else
						fprintf( stderr, " Error: Driver Unloaded!\n" );
				}
				else
					fprintf( stderr, " Error: LoadDriver\n" );
			}
			else
				fprintf( stderr, " Error: Init\n" );
		}
	}
	else
		fprintf( stderr, " Error: Other instance running!, please terminate the process with PID: %d\n", other_pid );

	printf( "\n PRESS ENTER TO EXIT.\n" );
	getchar();

	return 0;
}

