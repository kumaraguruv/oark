#include "debug.h"

debug = TRUE;

VOID DisplayErrorMsg(PCHAR pMsg, PCHAR pFunctName, DWORD line)
{
   fprintf(stderr, "[ERROR] [%s():line %u] Error: '%s' -> GetLastError() = %d.\n", pFunctName, line, pMsg, GetLastError()); 
}

VOID DisplayAllocationFailureMsg(PCHAR pFunctName, DWORD line)
{
    DisplayErrorMsg("Memory allocation failed", pFunctName, line);
}

VOID DisplayIOCTLFailureMsg(PCHAR pFunctName, DWORD line)
{
    DisplayErrorMsg("IOCTL_CHANGE_MODE, IOCTLReadKernMem failed", pFunctName, line);
}

VOID DisplayExceptionMsg(PCHAR pFunctName, DWORD line)
{
    fprintf(stderr, "[EXCEP] [%s():line %u] Exception catched, terminating process..\nPlease hit the keyboard to exit process..", pFunctName, line);
    getchar();
    ExitProcess(0);
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
				  fprintf( stderr, " Error: AdjustTokenPrivileges\n" );
		 } 
		 else
			fprintf( stderr, " Error: LookupPrivilegeValue\n" );
     } 
	else
		fprintf( stderr, " Error: OpenProcessToken\n" );

	return ST_ERROR;
}
