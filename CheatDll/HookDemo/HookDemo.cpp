// HookDemo.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Hook.h"

void HookTestDemo() {
	printf("TestDemo Hooked\r\n");
	return;
}

int TestDemo() {
	int x = 0x23132131;
	printf("TestDemo \r\n");
	return  (x + 0x123213 + 21312);
}

__declspec(naked)
void AsmUnlimitedSun() {
	__asm {
		add dword ptr[eax + 0x5560], 1000
		push 0x0430A17
		ret
	}
}

__declspec(naked)
void AsmRemoveCd() {
	__asm {
		add dword ptr[edi + 0x24], 9999
		mov eax, dword ptr[edi + 0x24]
		cmp eax, dword ptr[edi + 0x28]
		push 0x00487296
		ret
	}
}
void AddSun() {
	__try {
		char* BaseAddr = (char*)0x0019984C;
		BaseAddr = (char*)(*(ULONG*)BaseAddr);
		BaseAddr = BaseAddr + 0x5560;
		*(ULONG*)BaseAddr += 0x19;
	}
	__except (1) {

	}
}


/*

00487286 - 80 7F 49 00 - cmp byte ptr[edi + 49], 00
0048728A - 74 20 - je PlantsVsZombies.exe + 872AC
0048728C - 83 47 24 01 - add dword ptr[edi + 24], 01 <<
00487290 - 8B 47 24 - mov eax, [edi + 24]
00487293 - 3B 47 28 - cmp eax, [edi + 28]
00487296
*/
void RemoveCdTime() {
	char bytes[6] = { 0x68, 00, 00 ,00 ,00 , 0xC3 };
	char* func = (char*)(0x00487290);
	ULONG oldP = 0;
	VirtualProtect(func, 0x1000, PAGE_EXECUTE_READWRITE, &oldP);
	*(ULONG*)&bytes[1] = (ULONG)(AsmRemoveCd);
	memcpy((void*)func, bytes, 6);
	VirtualProtect(func, 0x1000, oldP, &oldP);
}

void ChangeValueOfSun() {
	char bytes[6] = { 0x68, 00, 00 ,00 ,00 , 0xC3 };

	char* func = (char*)(0x0430A11);
	ULONG oldP = 0;
	VirtualProtect(func, 0x1000, PAGE_EXECUTE_READWRITE, &oldP);
	*(ULONG*)&bytes[1] = (ULONG)(AsmUnlimitedSun);
	memcpy((void*)func, bytes, 6);
	VirtualProtect(func, 0x1000, oldP, &oldP);
}

void InvincibleMode() {
	char* PtrToAttackFunc = (char*)0x0052FCF0;
	ULONG oldP = 0;
	VirtualProtect(PtrToAttackFunc, 0x1000, PAGE_EXECUTE_READWRITE, &oldP);
	PtrToAttackFunc[3] = 0x0;
	VirtualProtect(PtrToAttackFunc, 0x1000, oldP, &oldP);
}
DWORD WINAPI ThreadProc(PVOID param) {
	ChangeValueOfSun();
	InvincibleMode();
	RemoveCdTime();
	while (1) {
		AddSun();
		// OutputDebugString(L"adding sun \r\n");
		Sleep(1000);
	}

	return 0;
}

bool g_CheatThreadCreated = false;
BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle,
	IN DWORD     nReason,
	IN LPVOID    Reserved)
{

	if (!g_CheatThreadCreated) {
		CreateThread(NULL, 0, ThreadProc, nullptr, 0, nullptr);
		g_CheatThreadCreated = true;
	}
	return true;
}

