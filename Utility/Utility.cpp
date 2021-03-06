// Utility.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include "stdafx.h"
#include "groupManipulation.h"


int main()
{
	HANDLE token;
	if (!tokenLib::aquireTokenWithPrivilegesForTokenManipulation(token))
		return 0;
	DWORD session_id = ::WTSGetActiveConsoleSessionId();

	if (!::SetTokenInformation(token, TokenSessionId, &session_id, sizeof DWORD))
		return 0;

	STARTUPINFO si = { sizeof si };
	si.lpDesktop = nullptr;

	PROCESS_INFORMATION pi;
	DWORD process_id = 0;

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = nullptr;
	sa.bInheritHandle = true;


	if (!::CreateProcessAsUser(
		token,
		L"C:\\Users\\PB-Win\\Desktop\\advanced_sec\\TokenManipulationUtility\\Debug\\TokenManipulator.exe",
		NULL,
		&sa,  // <- Process Attributes
		NULL,  // Thread Attributes
		false, // Inheritaion flags
			   // release build should not display console window
		0,
		NULL,  // Environment
		NULL,  // Current directory
		&si,   // Startup Info
		&pi))
	{
		getchar();
		return 0;
	}
	::WaitForSingleObject(pi.hProcess, 50000);
    return 0;
}

