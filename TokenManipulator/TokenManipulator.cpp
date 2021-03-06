// TokenManipulator.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include "groupManipulation.h"


int main()
{


	std::cout << "Successfull start" << std::endl;
	PSID groupPID;
	std::wstring groupName = std::wstring(L"shark_cage_group_dummy1");
	tokenLib::deleteLocalGroup(const_cast<wchar_t*>(groupName.c_str()));
	tokenLib::createLocalGroup(const_cast<wchar_t*>(groupName.c_str()), groupPID);
	PSID groupPID2;
	std::wstring groupName2 = std::wstring(L"shark_cage_group_dummy2");
	tokenLib::deleteLocalGroup(const_cast<wchar_t*>(groupName2.c_str()));
	tokenLib::createLocalGroup(const_cast<wchar_t*>(groupName2.c_str()), groupPID2);
	HANDLE token_handle = nullptr;


	if (!tokenLib::constructUserTokenWithMultipleGroups(std::vector<LPWSTR>{const_cast<wchar_t*>(groupName.c_str()), const_cast<wchar_t*>(groupName2.c_str())}, token_handle))
	{
		std::cout << "Cannot create required token" << std::endl;
		return 4;
	}
	STARTUPINFO info = {};
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = SW_SHOW;

	info.lpDesktop = nullptr;

	// Create the process.
	PROCESS_INFORMATION process_info = {};
	std::wstring app_path = std::wstring(L"cmd.exe /k whoami /groups");
	if (::CreateProcessWithTokenW(token_handle, LOGON_WITH_PROFILE, nullptr, const_cast<wchar_t*>(app_path.c_str()), 0, nullptr, nullptr, &info, &process_info) == 0)
	{
		std::cout << "Failed to start process. Error: " << ::GetLastError() << std::endl;
	}
	::WaitForSingleObject(process_info.hProcess, 50000);
	tokenLib::deleteLocalGroup(const_cast<wchar_t*>(groupName.c_str()));
	tokenLib::deleteLocalGroup(const_cast<wchar_t*>(groupName2.c_str()));

	token_handle = nullptr;

	if (!tokenLib::constructUserTokenWithMultiplePrivileges(std::vector<LPCWSTR>{L"SeDebugPrivilege", L"SeCreateTokenPrivilege",L"SeIncreaseBasePriorityPrivilege"},token_handle)) {
		std::cout << "Cannot create required token" << std::endl;
		return 4;
	}

	/////////////////////////////////

	DWORD buffer = 0;
	GetTokenInformation(token_handle, TokenPrivileges, nullptr, 0, &buffer);
	SetLastError(0);
	PTOKEN_PRIVILEGES data = (PTOKEN_PRIVILEGES) new BYTE[buffer];
	GetTokenInformation(token_handle, TokenPrivileges, data, buffer, &buffer);

	for (size_t i = 0; i < data->PrivilegeCount; i++)
	{
		DWORD bufferSize = 0;
		LookupPrivilegeName(nullptr, &(data->Privileges[i]).Luid, nullptr, &bufferSize);
		WCHAR* name = (LPTSTR) new BYTE[bufferSize * sizeof(TCHAR)];
		memset(name, 0, bufferSize * sizeof(TCHAR));
		LookupPrivilegeName(nullptr, &(data->Privileges[i]).Luid, name, &bufferSize);
		std::wcout << name << std::endl;
	}

	TOKEN_PRIVILEGES tp;
	LUID luid;
	SetLastError(0);
	if (!LookupPrivilegeValue(
		nullptr,            // lookup privilege on local system
		L"SeCreateTokenPrivilege",   // privilege to lookup
		&luid))        // receives LUID of privilege
	{
		std::cout << "Cannot lookup privilege" << std::endl;
		getchar();
	}
	if (GetLastError() != 0) std::cout << "Something went wrong" << std::endl;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(token_handle, false, &tp, sizeof(tp), (PTOKEN_PRIVILEGES)nullptr, (PDWORD)nullptr))
	{
		std::cout << "Cannot adjust privilege" << std::endl;
		getchar();
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		std::cout << "Privilege not here" << std::endl;
		getchar();
	}
	////////////////////////////////


	process_info = {};
	app_path = std::wstring(L"cmd.exe /k whoami /priv");
	if (::CreateProcessWithTokenW(token_handle, LOGON_WITH_PROFILE, nullptr, const_cast<wchar_t*>(app_path.c_str()), 0, nullptr, nullptr, &info, &process_info) == 0)
	{
		std::cout << "Failed to start process. Error: " << ::GetLastError() << std::endl;
	}
	::WaitForSingleObject(process_info.hProcess, 50000);
    return 0;
}

