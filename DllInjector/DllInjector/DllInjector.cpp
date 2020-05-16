// DllInjector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <psapi.h>
int GetProcessID(WCHAR* ProcessName)
{
	TOKEN_PRIVILEGES Token = { 0 };
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	// Get the list of process identifiers.
	DWORD processID = 0;

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}


	// Calculate how many process identifiers were returned.

	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.

	for (i = 0; i < cProcesses; i++)
	{
		HANDLE token = 0;
		Token = { 0 };
		if (aProcesses[i] != 0)
		{
			OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token);
			LookupPrivilegeValue(NULL, _T("SeDebugPrivilege"), &Token.Privileges[0].Luid);
			Token.PrivilegeCount = 1;
			Token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(token, FALSE, &Token, NULL, NULL, NULL);
				
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS ,FALSE, aProcesses[i]);

			printf("err= %x \r\n", GetLastError());
			if (NULL != hProcess)
			{
				HMODULE hMod;
				DWORD cbNeeded;

				if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
					&cbNeeded))
				{
					GetModuleBaseName(hProcess, hMod, szProcessName,
						sizeof(szProcessName) / sizeof(TCHAR));
				}
			}

			if (wcsstr(szProcessName, ProcessName)) {
				printf("Process= %ws \r\n", szProcessName);
				return aProcesses[i];
			}

			CloseHandle(hProcess);

		}
	}
	return 0;
}

bool Inject() {
	BOOL ok = FALSE; // Assume that the function fails
	HANDLE process = NULL, thread = NULL;
	PWSTR memory = NULL;

	__try {
		WCHAR* DllPath = L"C:\\CheatDll.dll";
		DWORD targetProcessId = GetProcessID(L"PlantsVsZombies.exe");
		
		printf("%d", targetProcessId);

		// Get a handle for the target process
		process = OpenProcess(
			PROCESS_QUERY_INFORMATION |   // Required by Alpha
			PROCESS_CREATE_THREAD |   // For CreateRemoteThread
			PROCESS_VM_OPERATION |   // For VirtualAllocEx
			PROCESS_VM_WRITE,             // For WriteProcessMemory
			FALSE, targetProcessId);
		if (!process) __leave;

		// Calculate the number of bytes required to store DLL path
		int numberOfCharacters = 1 + lstrlenW(DllPath);
		int numberOfBytes = numberOfCharacters * sizeof(wchar_t);

		// Allocate memory
		memory = (PWSTR)VirtualAllocEx(process, NULL, numberOfBytes, MEM_COMMIT, PAGE_READWRITE);
		if (!memory) __leave;

		// Write path to DLL
		if (!WriteProcessMemory(process, memory, (PVOID)DllPath, numberOfBytes, NULL)) __leave;

		// Get the address of LoadLibraryW in Kernell32.dll
		PTHREAD_START_ROUTINE loadLibraryFunction = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (!loadLibraryFunction) __leave;

		// Create a remote thread 
		thread = CreateRemoteThread(process, NULL, 0, loadLibraryFunction, memory, 0, NULL);
		if (!thread) __leave;

		// Wait for the remote thread to terminate
		WaitForSingleObject(thread, INFINITE);

		// We are done
		ok = true;
	}
	__finally {
		// Cleanup
		if (memory) VirtualFreeEx(process, memory, 0, MEM_RELEASE);
		if (thread) CloseHandle(thread);
		if (process) CloseHandle(process);
	}

	return ok;
}

int main()
{
	printf("Inject result= %x \r\n", Inject());
	getchar();
    return 0;
}

