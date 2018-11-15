// TokenManipulator.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include "groupManipulation.h"


int main()
{


	std::cout << "Successfull start";
	PSID groupPID;
	std::wstring groupName = std::wstring(L"shark_cage_group_dummy");
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
    return 0;
}

