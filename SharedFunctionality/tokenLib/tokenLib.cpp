#include "stdafx.h"

#include "groupManipulation.h"

#include <LM.h>
#include <Wtsapi32.h>
#include <Winternl.h>
#include <Psapi.h>
#include <iostream>
#include <optional>
#include <vector>
#include <string>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

std::optional<HANDLE> getCurrentUserToken();
bool changeTokenCreationPrivilege(bool privilegeStatus);
bool changeTcbPrivilege(bool privilegeStatus);
bool getGroupSid(LPWSTR groupName, PSID &sid);
bool hasSeCreateTokenPrivilege(const HANDLE processHandle);
bool hasSeTcbPrivilege(const HANDLE processHandle);
std::optional<std::vector<DWORD>> getAllProcesses();
std::optional<std::vector<DWORD>> getProcessesWithBothPrivileges(const std::vector<DWORD>& allProcesses);
std::optional<HANDLE> getProcessUnderLocalSystem(std::vector<DWORD> processes);
void inline reportError(std::wstring errorString);

class TokenParsingException : public std::exception {
public:
	const char * what() const throw () {
		return "Error encountered parsing template token";
	}
};

class tokenTemplate {

private:
	typedef NTSTATUS(__stdcall *NT_CREATE_TOKEN)(
		OUT PHANDLE             TokenHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN TOKEN_TYPE           TokenType,
		IN PLUID                AuthenticationId,
		IN PLARGE_INTEGER       ExpirationTime,
		IN PTOKEN_USER          TokenUser,
		IN PTOKEN_GROUPS        TokenGroups,
		IN PTOKEN_PRIVILEGES    TokenPrivileges,
		IN PTOKEN_OWNER         TokenOwner,
		IN PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
		IN PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
		IN PTOKEN_SOURCE        TokenSource
		);
	NT_CREATE_TOKEN NtCreateToken = NULL;

	ACCESS_MASK			accessMask;
	POBJECT_ATTRIBUTES	objectAttributes;
	TOKEN_TYPE			tokenType;
	PLUID				authenticationId;
	PLARGE_INTEGER		expirationTime;
	PTOKEN_USER         tokenUser;
	PTOKEN_GROUPS       tokenGroups;
	PTOKEN_PRIVILEGES   tokenPrivileges;
	PTOKEN_OWNER        tokenOwner;
	PTOKEN_PRIMARY_GROUP tokenPrimaryGroup;
	PTOKEN_DEFAULT_DACL tokenDefaultDacl;
	PTOKEN_SOURCE       tokenSource;
	PTOKEN_GROUPS		modifiedGroups;

	void cleanup();
public:
	tokenTemplate(HANDLE &userToken);
	~tokenTemplate();

	// these need to be customized if needed so memory of member pointers also gets copied
	// (otherwise there could be use-after-frees in the destructor)
	tokenTemplate(const tokenTemplate &) = delete;
	tokenTemplate operator=(const tokenTemplate &) = delete;

	bool addGroup(PSID sid);
	bool addMultipleGroups(std::vector<PSID> vSid);

	bool generateToken(HANDLE & token);
};

namespace tokenLib {

	DLLEXPORT bool createLocalGroup(LPWSTR groupName, PSID &sid) {
		LOCALGROUP_INFO_0 localGroupInfo;
		localGroupInfo.lgrpi0_name = groupName;


		NET_API_STATUS result = NetLocalGroupAdd(NULL, 0, (LPBYTE)&localGroupInfo, NULL);
		if (result != NERR_Success) {
			if (result == NERR_GroupExists) reportError(L"Specified group name already exists");
			else reportError(L"Could not create specified group");
			sid = NULL;
			return false;
		}

		return getGroupSid(groupName,sid);
	}

	DLLEXPORT bool destroySid(PSID &sid) {
		delete[](BYTE*) sid;
		sid = NULL;
		return true;
	}

	DLLEXPORT bool deleteLocalGroup(LPWSTR groupName) {
		if (NetLocalGroupDel(NULL, groupName) != NERR_Success)
			return false;
		return true;
	}

	DLLEXPORT bool constructUserTokenWithGroup(LPWSTR groupName, HANDLE &token) {
		PSID groupSid = nullptr;
		if (!getGroupSid(groupName,groupSid)){
			token = nullptr;
			return false;
		}
		if (!constructUserTokenWithGroup(groupSid, token))
		{
			token = nullptr;
			destroySid(groupSid);
			return false;
		}
		destroySid(groupSid);
		return true;
	}

	DLLEXPORT bool constructUserTokenWithMultipleGroups(std::vector<LPWSTR> groupNames, HANDLE &token) {
		std::vector<PSID> groupSids;
		for (auto& groupName : groupNames) {
			PSID groupSid = nullptr;
			if (!getGroupSid(groupName, groupSid)) {
				token = nullptr;
				return false;
			}
			groupSids.push_back(groupSid);
		}

		if (!constructUserTokenWithMultipleGroups(groupSids, token))
		{
			token = nullptr;
			for (auto& sid : groupSids) destroySid(sid);
			return false;
		}
		for (auto& sid : groupSids) destroySid(sid);
		return true;
	}

	DLLEXPORT bool constructUserTokenWithMultipleGroups(std::vector<PSID> groupSids, HANDLE &token) {
		//get handle to token of current process
		auto userTokenHandleOpt = getCurrentUserToken();
		if (!userTokenHandleOpt.has_value()) {
			reportError(L"Cannot aquire template token");
			return false;
		}
		HANDLE userToken = userTokenHandleOpt.value();

		//sample the token into individual structures
		std::unique_ptr<tokenTemplate> tokenDeconstructed{};
		try
		{
			tokenDeconstructed = std::make_unique<tokenTemplate>(userToken);
		}
		catch (const TokenParsingException& e)
		{
			printf("%s\n", e.what());
			CloseHandle(userToken);
			return false;
		}
		CloseHandle(userToken);

		//add desired group to the token
		if (!tokenDeconstructed->addMultipleGroups(groupSids)) {
			reportError(L"  Cannot add group to a token\n");
			return false;
		}

		//generate new access token
		if (!tokenDeconstructed->generateToken(token)) {
			reportError(L"  Cannot construct a token\n");
			return false;
		}
		return true;
	}

	DLLEXPORT bool constructUserTokenWithGroup(PSID sid, HANDLE &token) {
		return constructUserTokenWithMultipleGroups(std::vector<PSID>{sid}, token);
	}

	DLLEXPORT bool aquireTokenWithPrivilegesForTokenManipulation(HANDLE &token) {
		auto allProcessesOpt = getAllProcesses();
		if (!allProcessesOpt.has_value()) {
			reportError(L"Cannot enumerate processes");
			token = nullptr;
			return false;
		}
		auto allProcesses = allProcessesOpt.value();
		auto privilegedProcessesOpt = getProcessesWithBothPrivileges(allProcesses);
		if (!privilegedProcessesOpt.has_value())
		{
			reportError(L"Cannot locate process with needed privilege");
			token = nullptr;
			return false;
		}
		auto privilegedProcesses = privilegedProcessesOpt.value();

		auto processHandleOpt = getProcessUnderLocalSystem(privilegedProcesses);
		if (!processHandleOpt.has_value()) {
			reportError(L"Cannot locate process with needed privilege");
			token = nullptr;
			return false;
		}

		HANDLE processHandle = processHandleOpt.value();

		HANDLE processToken = nullptr;
		if (!OpenProcessToken(processHandle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &processToken)) {
			token = nullptr;
			CloseHandle(processHandle);
			reportError(L"Cannot aquire token handle");
			return false;
		}
		if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &token)) {
			token = nullptr;
			CloseHandle(processHandle);
			CloseHandle(processToken);
			reportError(L"Cannot duplicate token");
			return false;
		}
		CloseHandle(processHandle);
		CloseHandle(processToken);
		return true;
	}
}

//private code
std::optional<std::vector<DWORD>> getAllProcesses() {

	std::vector<DWORD> processes(1024); //arbitrary number, chosen as power of 2 for allignment
	DWORD usedBufferSize = 0;
	do
	{
		processes.reserve(2 * processes.capacity());
		if (!EnumProcesses(&(processes[0]), processes.capacity(), &usedBufferSize))
		{
			reportError(L"Cannot enumerate processes on the system");
			return std::nullopt;
		}
		processes.resize(usedBufferSize/sizeof(DWORD)); //restore vector integrity
	} while (usedBufferSize / sizeof(DWORD) >= processes.capacity());
	return processes;
}

std::optional<std::vector<DWORD>> getProcessesWithBothPrivileges(const std::vector<DWORD>& allProcesses) {
	std::vector<DWORD> processes;
	for (auto const& processPid: allProcesses)
	{
		HANDLE processHandle;
		if ((processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processPid)) == NULL) continue;
		try
		{
			if (hasSeCreateTokenPrivilege(processHandle) && hasSeTcbPrivilege(processHandle))
			{
				processes.push_back(processPid);
			}
		}
		catch (const std::exception&)
		{
			CloseHandle(processHandle);
			throw;
		}
		CloseHandle(processHandle);
	}
	if (processes.size() == 0) {
		reportError(L"Could not find process with SeCreateTokenPrivilege");
		return std::nullopt;
	}
	return processes;
}

bool hasPrilivege(const HANDLE processHandle, LPCTSTR privilege) {
	HANDLE tokenHandle = nullptr;
	if (!OpenProcessToken(processHandle, TOKEN_ALL_ACCESS, &tokenHandle)) {
		reportError(L"Cannot open process token");
		return false;
	}
	DWORD bufferSize = 0;
	GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES) new BYTE[bufferSize];
	GetTokenInformation(tokenHandle, TokenPrivileges, (LPVOID)tokenPrivileges, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		CloseHandle(tokenHandle);
		delete[](BYTE*) tokenPrivileges;
		reportError(L"Cannot query selected token");
		return false;
	}

	for (size_t i = 0; i < tokenPrivileges->PrivilegeCount; i++)
	{
		bufferSize = 0;
		LookupPrivilegeName(NULL, &(tokenPrivileges->Privileges[i]).Luid, NULL, &bufferSize);
		LPTSTR name = (LPTSTR) new BYTE[bufferSize * sizeof(TCHAR)];
		LookupPrivilegeName(NULL, &(tokenPrivileges->Privileges[i]).Luid, name, &bufferSize);
		if (wcscmp(name, privilege) == 0)
		{
			CloseHandle(tokenHandle);
			delete[](BYTE*) tokenPrivileges;
			delete[](BYTE*) name;
			return true;
		}
		delete[](BYTE*) name;
	}
	reportError(L"Selected token does not posses SeCreateTokenPrivilege");
	CloseHandle(tokenHandle);
	delete[](BYTE*) tokenPrivileges;
	return false;
}

bool hasSeCreateTokenPrivilege(const HANDLE processHandle) {
	return hasPrilivege(processHandle, SE_CREATE_TOKEN_NAME);
}

bool hasSeTcbPrivilege(const HANDLE processHandle){
	return hasPrilivege(processHandle, SE_TCB_NAME);
}

bool processIsLocalSystem(HANDLE processHandle) {
	HANDLE processToken = nullptr;
	if (!OpenProcessToken(processHandle, TOKEN_QUERY, &processToken))
	{
		reportError(L"Cannot determine if process is local system");
		return false;
	}

	DWORD bufferSize = 0;
	GetTokenInformation(processToken, TokenUser, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_USER tokenUser = (PTOKEN_USER) new BYTE[bufferSize];
	if (!GetTokenInformation(processToken, TokenUser, (LPVOID)tokenUser, bufferSize, &bufferSize)) {
		delete[](BYTE*) tokenUser;
		reportError(L"Cannot get token information");
		return false;
	}

	DWORD sidSize = SECURITY_MAX_SID_SIZE;
	PSID systemSID = (PSID) new BYTE[sidSize];
	if (!CreateWellKnownSid(WinLocalSystemSid, NULL, systemSID, &sidSize)){
		delete[](BYTE*) tokenUser;
		delete[](BYTE*) systemSID;
		reportError(L"Cannot create system SID");
		return false;
	}

	if (!EqualSid(systemSID, tokenUser->User.Sid)) {
		delete[](BYTE*) systemSID;
		delete[](BYTE*) tokenUser;
		return false;
	}

	delete[](BYTE*) systemSID;
	delete[](BYTE*) tokenUser;
	return true;
}

std::optional<HANDLE> getProcessUnderLocalSystem(std::vector<DWORD> processes){
	for (auto const& processPid : processes)
	{
		HANDLE processHandle;
		if ((processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processPid)) == NULL) continue;
		try
		{
			if (processIsLocalSystem(processHandle))
			{
				return processHandle;
			}
		}
		catch (const std::exception&)
		{
			CloseHandle(processHandle);
			throw;
		}
		CloseHandle(processHandle);
	}
	return std::nullopt;
}

ULONG getCurrentSessionID() {
	DWORD count = 0;
	PWTS_SESSION_INFO  info;
	WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count);
	for (size_t i = 0; i < count; i++)
	{
		if (lstrcmp(info[i].pWinStationName, L"Console") == 0)
		{
			return info[i].SessionId;
		}

	}
	return 0;
}

std::optional<HANDLE> getCurrentUserToken() {
	HANDLE userToken = 0;
	ULONG sessionId = ::WTSGetActiveConsoleSessionId();
	if (!changeTcbPrivilege(true)) {
		reportError(L"Cannot aquire SE_TCB_NAME privilege needed");
		return std::nullopt;
	}
	if (!WTSQueryUserToken(sessionId, &userToken)) {
		reportError(L"Cannot query user token");
		changeTcbPrivilege(false);
		return std::nullopt;
	}
	changeTcbPrivilege(false);
	HANDLE duplicatedUserToken = nullptr;
	if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicatedUserToken)) {
		reportError(L"Cannot duplicate token");
		return std::nullopt;
	}
	CloseHandle(userToken);
	return duplicatedUserToken;
}

bool getGroupSid(LPWSTR groupName, PSID &sid) {
	SID_NAME_USE accountType;
	DWORD bufferSize = 0, buffer2Size = 0;

	LookupAccountName(NULL, groupName, NULL, &bufferSize, NULL, &buffer2Size, &accountType);
	sid = (PSID) new BYTE[bufferSize];
	LPTSTR domain = (LPTSTR) new BYTE[buffer2Size * sizeof(TCHAR)];
	if (!LookupAccountName(NULL, groupName, sid, &bufferSize, domain, &buffer2Size, &accountType)) {
		reportError(L"Could not retrieve SID of newly created group");
		NetLocalGroupDel(NULL, groupName);
		delete[](BYTE*) sid;
		delete[](BYTE*) domain;
		sid = NULL;
		return false;
	}
	delete[](BYTE*) domain;
	return true;
}


//adopted from MSDN example
bool setPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool changePrivilege(bool privilegeStatus, LPCTSTR privilege) {
	HANDLE currentProcessHandle;
	HANDLE userTokenHandle;
	currentProcessHandle = GetCurrentProcess();
	if (!OpenProcessToken(currentProcessHandle, TOKEN_ALL_ACCESS, &userTokenHandle)) {
		reportError(L"Error getting token for privilege escalation\n");
		return false;
	}

	auto set_privilege_status = setPrivilege(userTokenHandle, privilege, privilegeStatus);

	CloseHandle(userTokenHandle);
	return set_privilege_status;
}

bool changeTokenCreationPrivilege(bool privilegeStatus) {
	return changePrivilege(privilegeStatus, SE_CREATE_TOKEN_NAME);
}

bool changeTcbPrivilege(bool privilegeStatus){
	return changePrivilege(privilegeStatus, SE_TCB_NAME);
}

void tokenTemplate::cleanup()
{
	if (objectAttributes != nullptr) delete static_cast<PSECURITY_QUALITY_OF_SERVICE>(objectAttributes->SecurityQualityOfService);
	delete objectAttributes;
	delete authenticationId;
	delete expirationTime;
	delete[](BYTE*) tokenUser;
	delete[](BYTE*) tokenGroups;
	delete[](BYTE*) modifiedGroups;
	delete[](BYTE*) tokenPrivileges;
	delete[](BYTE*) tokenOwner;
	delete[](BYTE*) tokenPrimaryGroup;
	delete[](BYTE*) tokenDefaultDacl;
	delete[](BYTE*) tokenSource;
}

tokenTemplate::tokenTemplate(HANDLE &userToken) : objectAttributes{ nullptr }, authenticationId{ nullptr }, expirationTime{ nullptr },
													tokenUser{ nullptr }, tokenGroups{ nullptr }, tokenPrivileges{ nullptr }, tokenOwner{ nullptr },
													tokenPrimaryGroup{ nullptr }, tokenDefaultDacl{ nullptr }, tokenSource{ nullptr } {

	//load internal NtCreateToken function
	HMODULE hModule = LoadLibrary(L"ntdll.dll");
	NtCreateToken = (NT_CREATE_TOKEN)GetProcAddress(hModule, "NtCreateToken");

	//parse token
	DWORD bufferSize = 0;
	GetTokenInformation(userToken, TokenType, NULL, 0, &bufferSize);
	SetLastError(0);
	GetTokenInformation(userToken, TokenType, (LPVOID)&tokenType, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenUser, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenUser = (PTOKEN_USER) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenUser, (LPVOID)tokenUser, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenGroups, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenGroups = (PTOKEN_GROUPS) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenGroups, (LPVOID)tokenGroups, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenPrivileges, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenPrivileges = (PTOKEN_PRIVILEGES) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenPrivileges, (LPVOID)tokenPrivileges, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenOwner, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenOwner = (PTOKEN_OWNER) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenOwner, (LPVOID)tokenOwner, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenPrimaryGroup, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenPrimaryGroup = (PTOKEN_PRIMARY_GROUP) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenPrimaryGroup, (LPVOID)tokenPrimaryGroup, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenDefaultDacl, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenDefaultDacl = (PTOKEN_DEFAULT_DACL) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenDefaultDacl, (LPVOID)tokenDefaultDacl, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenSource, NULL, 0, &bufferSize);
	SetLastError(0);
	tokenSource = (PTOKEN_SOURCE) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenSource, (LPVOID)tokenSource, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	bufferSize = 0;
	GetTokenInformation(userToken, TokenStatistics, NULL, 0, &bufferSize);
	SetLastError(0);
	PTOKEN_STATISTICS stats = (PTOKEN_STATISTICS) new BYTE[bufferSize];
	GetTokenInformation(userToken, TokenStatistics, (LPVOID)stats, bufferSize, &bufferSize);
	if (GetLastError() != 0)
	{
		this->cleanup();
		throw TokenParsingException();
	}

	expirationTime = new LARGE_INTEGER{ stats->ExpirationTime };
	authenticationId = new LUID{ stats->AuthenticationId };

	accessMask = TOKEN_ALL_ACCESS;

	PSECURITY_QUALITY_OF_SERVICE sqos =
		new SECURITY_QUALITY_OF_SERVICE{ sizeof(SECURITY_QUALITY_OF_SERVICE), stats->ImpersonationLevel, SECURITY_STATIC_TRACKING, FALSE };
	POBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES{ sizeof(OBJECT_ATTRIBUTES), 0, 0, 0, 0, sqos };
	objectAttributes = oa;

	modifiedGroups = NULL;

	delete[](BYTE*) stats;
}

tokenTemplate::~tokenTemplate() {
	this->cleanup();
}

inline bool tokenTemplate::addGroup(PSID sid) {

	return addMultipleGroups(std::vector<PSID>{sid});
}

inline bool tokenTemplate::addMultipleGroups(std::vector<PSID> vSid){
	if (modifiedGroups != NULL) {
		reportError(L"A group was already added. Cannot perform more than one modification\n");
		return false;
	}
	DWORD groupCount = tokenGroups->GroupCount;
	std::vector<SID_AND_ATTRIBUTES> additionalGroups;
	for (size_t i = 0; i < vSid.size(); i++)
	{
		additionalGroups.push_back(SID_AND_ATTRIBUTES{ vSid.at(i), SE_GROUP_ENABLED });
	}

	modifiedGroups = (PTOKEN_GROUPS) new BYTE[(FIELD_OFFSET(TOKEN_GROUPS, Groups[groupCount + vSid.size()]))];
	//note: this is a somewhat shallow copy, Sid attribute is of type PSID, the actual SID entries are kept in original memory of tokenGroups - modifiedGroups is no longer usable after deallocation of tokenGroups
	for (size_t i = 0; i < groupCount; i++)
	{
		modifiedGroups->Groups[i] = tokenGroups->Groups[i];
	}
	for (size_t i = 0; i < additionalGroups.size(); i++) {
		modifiedGroups->Groups[groupCount+i] = additionalGroups.at(i);
	}
	
	modifiedGroups->GroupCount = groupCount + vSid.size();
	return true;
}

inline bool tokenTemplate::generateToken(HANDLE & token) {

	//enable needed privileges
	if (!changeTokenCreationPrivilege(true)) {
		reportError(L"  Cannot aquire needed privileges\n");
		return false;
	}

	HANDLE newToken = nullptr;
	PTOKEN_GROUPS groups = NULL;

	if (modifiedGroups == NULL) { //token not modified
		groups = tokenGroups;
	}
	else {
		groups = modifiedGroups;
	}
	//construct token
	NTSTATUS status = NtCreateToken(
		&newToken,
		accessMask,
		objectAttributes,
		tokenType,
		authenticationId,
		expirationTime,
		tokenUser,
		groups,
		tokenPrivileges,
		tokenOwner,
		tokenPrimaryGroup,
		tokenDefaultDacl,
		tokenSource
	);

	//cleanup of privileges
	changeTokenCreationPrivilege(false);

	if (!NT_SUCCESS(status)) {
		reportError(L"  Cannot create modified token\n");
		token = NULL;
		return false;
	}

	token = newToken;
	return true;
}

void inline reportError(std::wstring errorString) {
	//TODO: elaborate more on error reporting
	std::wcout << errorString << std::endl;
}