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
#include "common.h"

BOOL debug = TRUE;

STATUS_t EnableDebugPrivilege( void );

int main( void )
{
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
		printf( " Error: EnableDebugPrivilege\n" );
	else if ( debug )
		printf( " OK: EnableDebugPrivilege\n" );

	printf( "\n PRESS ENTER TO EXIT.\n" );
	getchar();

	return 0;
}


STATUS_t EnableDebugPrivilege( void ) 
{ 
	HANDLE hToken; 
    TOKEN_PRIVILEGES tokenPriv; 
	LUID luidDebug; 

	if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, & hToken ) ) 
	{ 
		 if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, & luidDebug ) ) 
		 { 
			  tokenPriv.PrivilegeCount = 1; 
			  tokenPriv.Privileges[0].Luid = luidDebug; 
			  tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
			  if ( AdjustTokenPrivileges( hToken, FALSE, & tokenPriv, sizeof( tokenPriv ), NULL, NULL ) )
				return ST_OK;
			  else
				  printf( " Error: AdjustTokenPrivileges\n" );
		 } 
		 else
			printf( " Error: LookupPrivilegeValue\n" );
     } 
	else
		printf( " Error: OpenProcessToken\n" );

	return ST_ERROR;
}
