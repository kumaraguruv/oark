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

#ifndef _INIT_H__
#define _INIT_H__

#include "others.h"
#include "ssdt.h"
#include "idt.h"
#include "pebhooking.h"

typedef STATUS_t (* INIT_TABLE_ENTRY_FUNC_t)( FUNC_ARGS_t *, FUNC_ARGS_GLOBAL_t * );

typedef struct INIT_TABLE_ENTRY_s
{
    FUNC_ARGS_t                 function_args;
    INIT_TABLE_ENTRY_FUNC_t     function;
    BOOLEAN                     enable;
    char                      * name;
	int							id;

} INIT_TABLE_ENTRY_t;

typedef struct ARGUMENT_PARSER_TABLE_s
{
	char		*	command_line_flag;
	char		*	command_line_description;
	FUNC_ARGS_t		function_arg;
	int				init_table_entry_id;

} ARGUMENT_PARSER_TABLE_t;

extern INIT_TABLE_ENTRY_t INIT_TABLE[];

STATUS_t ArgumentParser( int argc, char * argv[] );
STATUS_t InitCalls( HANDLE );
void PrintOptions( void );

#endif /* _INIT_H__ */
