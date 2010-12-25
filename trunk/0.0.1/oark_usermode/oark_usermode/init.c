/*
Copyright (c) <2010> <Dreg aka David Reguera Garcia, dreg@fr33project.org>
Copyright (c) <2010> <George Nicolaou, nicolaou.george@gmail.com>

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

#include "init.h"
#include "msr.h"

ARGUMENT_PARSER_TABLE_t ARG_TABLE[] =
{
	{ "S", "SSDT Hook detection module with default options", {FIN_SSDT_DEFAULTS}, 0 },
    { "Ss", "Display hooked SSDT System entries", {FIN_SSDT_SYSTEM}, 0},
	{ "Sh", "Display hooked SSDT Shadow entries", {FIN_SSDT_SHADOW}, 0 },
	{ "Sx", "Display potential hook in KTHREAD.ServiceTable field (Xrayn POC)", {FIN_SSDT_XRAYN}, 0 },
	{ "P", "PEB Hook detection module with default options", {FIN_PEBHOOKING_DEFAULTS}, 3 },
	{ "E", "SYSENTER Hook detection module with default options", {FIN_SYSENTER_DEFAULTS}, 1 },
	{ "I", "Print IDT Information", {FIN_IDT_DEFAULTS}, 2 }
};

INIT_TABLE_ENTRY_t INIT_TABLE[] =
{
    { {FIN_SSDT_DEFAULTS}, CheckSSDTHooking, TRUE, "SSDT HOOKING DETECTION", 0 },
    { {FIN_SYSENTER_DEFAULTS}, CheckSysenterHookDetection, TRUE, "SYSENTER HOOKING DETECTION", 1 },
    { {FIN_IDT_DEFAULTS}, idt, TRUE, "IDT INFORMATION", 2 },
    { {FIN_PEBHOOKING_DEFAULTS}, CheckPEBHooking, TRUE, "PEB HOOKING DETECTION", 3 }
};

void PrintOptions()
{
	int i;

	printf("Each option can be enabled using the plus (+) symbol and disabled using the minus (-) symbol\n");
	printf( "-h \t Display usage help\n-l \t Display default features\n");
	for ( i = 0; i < ( sizeof( ARG_TABLE ) / sizeof( * ARG_TABLE ) ); i++ )
	{
		printf( "+%s \t%s\n", ARG_TABLE[i].command_line_flag, ARG_TABLE[i].command_line_description );
	}
}

VOID PrintEnabled()
{
	int i,j;
	int id;

	for ( i = 0; i < ( sizeof( INIT_TABLE ) / sizeof( * INIT_TABLE ) ); i++ )
	{
		printf
			( 
				"[%s] %s\n",
				( INIT_TABLE[i].enable == TRUE ) ? "Enabled" : "Disabled",
				INIT_TABLE[i].name
			 );
		if(INIT_TABLE[i].enable == TRUE)
		{
			j = 0;
			id = INIT_TABLE[i].id;
			while( j < ( sizeof( ARG_TABLE ) / sizeof( * ARG_TABLE ) ) )
			{
				if ( ARG_TABLE[j].init_table_entry_id == id )
				{
					if ( ARG_TABLE[j].function_arg.flags & INIT_TABLE[i].function_args.flags )
						printf( "\t%s\n", ARG_TABLE[j].command_line_description );
				}
				++j;
			}
		}
	}

}

VOID ZeroInitTable()
{
	int i;
	
	for ( i = 0; i < ( sizeof( INIT_TABLE ) / sizeof( * INIT_TABLE ) ); i++ )
		INIT_TABLE[i].function_args.flags = (DWORD)NULL;
}

VOID UpdateEnabledModules()
{
	int i;

	for ( i = 0; i < ( sizeof( INIT_TABLE ) / sizeof( * INIT_TABLE ) ); i++ )
		INIT_TABLE[i].enable = ( INIT_TABLE[i].function_args.flags == (DWORD)NULL ) ? FALSE : TRUE;

}

STATUS_t ArgumentParser(int argc, char *argv[])
{
	int						i,
							j = 0;
	BOOLEAN					onoff_switch;
	char				*	argument;
	INIT_TABLE_ENTRY_t	*	init_entry;
	
	argument = argv[1];
	argument++;

	switch(*argument)
	{
		case 'h': PrintOptions(); return ST_ERROR;
		case 'l': PrintEnabled(); return ST_ERROR;
	}

	ZeroInitTable();

	for ( i = 1; i < argc; i++ )
	{
		argument = argv[i];

		if ( *argument == '+' )
			onoff_switch = TRUE;
		else if ( *argument == '-' )
			onoff_switch = FALSE;
		else 
		{
			printf("Argument %d is not a valid argument\n", i);
			return ST_ERROR;
		}

		++argument;

		j = 0;
		while( j < ( sizeof(ARG_TABLE) / sizeof( * ARG_TABLE ) ) )
		{
			if( memcmp( argument, ARG_TABLE[j].command_line_flag, 2 ) == 0 )
			{
				init_entry = &INIT_TABLE[ARG_TABLE[j].init_table_entry_id];
				
				/* OR the flag bit */
				init_entry->function_args.flags |= ARG_TABLE[j].function_arg.flags;
				
				/* Remove flag bit if requested */
				if ( onoff_switch == FALSE )
					init_entry->function_args.flags ^= ARG_TABLE[j].function_arg.flags;
				break;
			}
			++j;
		}
	}

	UpdateEnabledModules();

	if ( debug )
		PrintEnabled();
	
	return ST_OK;
}


STATUS_t InitCalls( HANDLE hdevice )
{
    int i;
    static FUNC_ARGS_GLOBAL_t globals;

    globals.hdevice = hdevice;

    for ( i = 0; i < ( sizeof( INIT_TABLE ) / sizeof( * INIT_TABLE ) ); i++ )
    {
        if 
        ( 
            ( INIT_TABLE[i].enable )
            && 
            ( INIT_TABLE[i].function_args.flags != 0 )
        )
        {
            printf(" > Calling %s module..", INIT_TABLE[i].name);
            printf("%s\n", (INIT_TABLE[i].function( & INIT_TABLE[i].function_args, & globals ) == ST_OK) ? "OK": "KO");
        }
    }

    return ST_OK;
}



