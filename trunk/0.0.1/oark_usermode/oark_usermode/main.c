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

#include <stdio.h>
#include <windows.h>
#include "debug.h"
#include "common.h"
#include "driverusr.h"
#include "idt.h"

int main( void )
{
	HANDLE device;

	printf
	( 
		"\n"
		" +-----------------------------------------------------------------+\n"
		" | oark - The Open Source Anti Rootkit v%s                      |\n"
		" | MIT License - http://code.google.com/p/oark/                    |\n"
		" |                                                                 |\n"  
		" | Main Developers (Alphabetical order):                           |\n"
		" |   - Dreg aka David Reguera Garcia - Dreg@fr33project.org        |\n"
		" |                                                                 |\n"
		" | Credits / Greetings (Alphabetical order):                       |\n"
		" |   - EP_X0FF aka DiabloNova (Rootkit Unhooker inspiration)       |\n" 
		" +-----------------------------------------------------------------+\n"
		"\n"
		, 
		OARK_VERSION 
	);

	if ( EnableDebugPrivilege() == ST_ERROR )
		fprintf( stderr, " Error: EnableDebugPrivilege\n" );
	else
	{
		if ( debug )
			printf( " OK: EnableDebugPrivilege\n" );

		if ( LoadDriver( & device ) )
		{
			if ( debug )
				printf( " OK: Driver Loaded!\n" );

			printf( " INFO: Searching in IDT:\n" );
			idt( device );

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

	printf( "\n PRESS ENTER TO EXIT.\n" );
	getchar();

	return 0;
}