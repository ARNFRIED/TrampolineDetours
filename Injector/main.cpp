#include<iostream>
#include<Windows.h>
#include<tlhelp32.h>
#include<string>
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

string injected = "Injected.dll";
string wow = "WoW.exe";
string injector = "Injector.exe";

void EnablePrivilege();
int GetRemoteModuleHandle(const int processId, string& moduleName);
int GetProcessId(string& processName);

auto CRTWithWait(const HANDLE hProcess, LPTHREAD_START_ROUTINE pFunc, void* pParam)
{
	HANDLE newThread = CreateRemoteThread(hProcess, 0, 0, pFunc, pParam, 0, 0);
	auto res = WaitForSingleObject(newThread, INFINITE);
	//MessageBox(0, "after wait", "Injector", MB_OK);
	DWORD injectedAddress{};
	GetExitCodeThread(newThread, &injectedAddress);
	CloseHandle(newThread);
	return injectedAddress;
}

auto Inject(const HANDLE hProcess, const char* argument)
{
	if (GetRemoteModuleHandle(GetProcessId(wow), injected))
		return;

	auto pArgument = VirtualAllocEx(hProcess, 0, strlen(argument), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pArgument, argument, strlen(argument), 0);
	auto pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	auto injectedAddress = CRTWithWait(hProcess, pLoadLibrary, pArgument);
	VirtualFreeEx(hProcess, pArgument, strlen(argument), MEM_RELEASE);
}

//-----------------------------------------------
// WinMain
//
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine,	int nCmdShow)
{
	CreateMutex(0, FALSE, "InjectorMutex");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return -1;

	if (!GetProcessId(wow))
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		CreateProcess("d:\\_Vanilla\\wow.exe", "", 0, 0, 0, 0, 0, 0, &si, &pi);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	while (!FindWindow(0, "World of Warcraft")) {}
	
	EnablePrivilege();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, true, GetProcessId(wow));

	char path[MAX_PATH];
	auto injectorPathSize = GetModuleFileName(0, path, MAX_PATH);
	auto curr_dir = string(path).substr(0, string(path).find_last_of("\\/") + 1);
	auto to_inject = curr_dir + injected;

	Inject(hProcess, to_inject.c_str());
	while (FindWindow(0, "World of Warcraft"))
	{
		if (GetAsyncKeyState(VK_NUMPAD9))
		{
			Inject(hProcess, to_inject.c_str());
			Sleep(1000);
		}
	}
	return 0;
}

void EnablePrivilege()
{
	HANDLE              hToken;
	TOKEN_PRIVILEGES    tp;
	LUID                luid;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken);
	LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	CloseHandle(hToken);
}

int GetRemoteModuleHandle(const int processId, string& moduleName)
{
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32W);
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

	if (!Module32First(hModule, &me32))
	{
		CloseHandle(hModule);
		return 0;
	}

	while (string(me32.szModule) != moduleName && Module32Next(hModule, &me32)) {}

	CloseHandle(hModule);

	if (string(me32.szModule) == moduleName)
		return (int)me32.modBaseAddr;

	return 0;
}

int GetProcessId(string& processName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!Process32First(hProcess, &pe32))
	{
		CloseHandle(hProcess);
		return 0;
	}

	while (string(pe32.szExeFile) != processName && Process32Next(hProcess, &pe32)) {}

	CloseHandle(hProcess);

	if (string(pe32.szExeFile) == processName)
		return (int)pe32.th32ProcessID;

	return 0;
}