#include "debug.h"

debug = TRUE;


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
				  fprintf( stderr, " Error: AdjustTokenPrivileges\n" );
		 } 
		 else
			fprintf( stderr, " Error: LookupPrivilegeValue\n" );
     } 
	else
		fprintf( stderr, " Error: OpenProcessToken\n" );

	return ST_ERROR;
}
