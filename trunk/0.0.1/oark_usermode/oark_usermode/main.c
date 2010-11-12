#include <stdio.h>

#define OARK_VERSION "0.0.1"

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

	getchar();

	return 0;
}