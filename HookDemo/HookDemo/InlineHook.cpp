#pragma once
#include "stdafx.h"
#include <Windows.h>
#include "LDasm.h"
#include "Hook.h"
#define NEW_JMP_FUNC_OFFSET		2
#define NEW_FUNC_OFFSET			3
#define OLD_BYTECODE_OFFSET		9
#define OLD_JMP_FUNC_OFFSET		15
#define OLD_FUNC_OFFSET			16

#define CALC_JMP_OFFSET(TargetAddr, CurrentAddr) (LONG)((LONG)TargetAddr - (LONG)CurrentAddr - 5)
#define GET_JMP_ADDRESS(CurrentAddr) (LONG)((LONG)CurrentAddr + *(LONG*)&(((CHAR*)CurrentAddr)[1]) + 5)



char ShellCodeTemplate[] = {
	(char)0x9C,																//pushfd
	(char)0x60,																//pushad
	(char)0xE8, (char)00, (char)00 , (char)00, (char)00,					//call new function
	(char)0x61,																//popad
	(char)0x9D,																//popfd
	(char)0x90, (char)0x90, (char)0x90, (char)0x90,	(char)0x90, (char)0x90,	// 5 or 6 old byte code
	(char)0xE9, (char)00, (char)00 ,(char)00 ,(char)00						//jmp to old Function Code + InstLen

};

BOOL InlineUnHook(_In_ HOOKINFO* Info) 
{
	ULONG oldProtect = 0;
	ULONG ShellCodeSize = 0;
	BOOL  ret = false;
	if (!Info) 
	{
		return false;
	}
	ret = VirtualProtect(Info->OldFunc, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!ret) {
		return false;
	}
	memcpy(Info->OldFunc, &Info->ShellCode[OLD_BYTECODE_OFFSET], Info->OldByteLen);
	
	if ((Info->ShellCode[OLD_BYTECODE_OFFSET] == (char)0xE9) ||
		(Info->ShellCode[OLD_BYTECODE_OFFSET] == (char)0xE8))
	{
		LONG JmpAddr = GET_JMP_ADDRESS(&Info->ShellCode[OLD_BYTECODE_OFFSET]);
		*(PLONG)&((char*)Info->OldFunc)[1] = CALC_JMP_OFFSET(JmpAddr,Info->OldFunc);
	}

	ret = VirtualProtect(Info->OldFunc, 0x1000, oldProtect, &oldProtect);
	if (!ret) {
		return false;
	}

	return true;
}

int InlineHook(
	_In_ void*		OldFunc,
	_In_ void*		NewFunc,
	_In_ ULONG		HookSize,
	_Out_ HOOKINFO* Info)
{

	HOOKINFO info = { 0 };
	ULONG oldProtect = 0;
	ULONG InstLen = 0;
	ULONG ShellCodeSize = 0;
	int  ret = false;
	CHAR  E9JmpCode[] = { (CHAR)0xE9, (CHAR)00, (CHAR)00 ,(CHAR)00,(CHAR)00 };
	CHAR  PushRetJmpCode[] = { (CHAR)0x66, (CHAR)00, (CHAR)00, (CHAR)00, (CHAR)00, (CHAR)0xC3 };
	do 
	{
		ret = VirtualProtect(OldFunc, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
		if (!ret) 
		{
			ret = HOOK_INST_NON_WRITEABLE;
			break;
		}

		while (InstLen < HookSize) 
		{
			InstLen += SizeOfCode((char*)OldFunc + InstLen, nullptr);
		}

		if (InstLen != HookSize) 
		{
			ret = HOOK_INST_LEN_MISTMATCH;
			break;
		}

		// Building ShellCode Buffer
		// In-memory Layout
		/*-------------------------------------------------------------------
		| + 0x0	 | pushfd								
		| + 0x1  | pushad				
		| + 0x2  | call NewFunction Addr
		| + 0x7  | popad
		| + 0x8  | popfd
		| + 0x9  | original Byte Code Copy from old function							
		| + 0x15 | Jmp to old function + hook lenght
		-------------------------------------------------------------------*/

		info.ShellCode = (char*)VirtualAlloc(0, sizeof(ShellCodeTemplate), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!info.ShellCode) 
		{
			ret = HOOK_INST_MEM_NOT_ENOUGH;
			break;
		}

		// Important:
		//   Since newly allocated memory is not promised to be cleaned, and if there's garbage bytes.
		//	 shellcode will be parsed error by CPU		
		RtlZeroMemory(info.ShellCode, ShellCodeSize);

		// Set bytes of new function call in shellcode template
		// Important:
		//	JMP Instruction is relative JMP,  it calculated by Offset = TargetAddress - CurrentAddress - 5
		*(ULONG*)&ShellCodeTemplate[NEW_FUNC_OFFSET] = CALC_JMP_OFFSET(
			(char*)NewFunc,
			&info.ShellCode[NEW_JMP_FUNC_OFFSET]
		);

		memcpy(&ShellCodeTemplate[OLD_BYTECODE_OFFSET], OldFunc, InstLen);

		//Important:
		//	Original instruction can also be JMP or CALL, not proligue if it's the case
		//  we have to relocate it to the shellcode buffer, instead of just copy into our 
		//  shellcode template
		if ((ShellCodeTemplate[OLD_BYTECODE_OFFSET] == (char)0xE9) ||
			(ShellCodeTemplate[OLD_BYTECODE_OFFSET] == (char)0xE8))
		{
			//Get Jmp Address by parsing the JMP assembly instruction 
			//It caculated as : Jmp Address = CurrentAddress + *(PULONG)(CurrentAddress + 1) + 5
			//Offset can be either negative or positive
			LONG JmpAddr = GET_JMP_ADDRESS(OldFunc);

			*(PLONG)&ShellCodeTemplate[OLD_BYTECODE_OFFSET + 1] = CALC_JMP_OFFSET(
				JmpAddr,
				&info.ShellCode[OLD_BYTECODE_OFFSET]
			);
		}

		//Important:
		//	Jmp back to original instruction + instruction lenght, means next instruction
		//	Because the original bytes code is already get executed in our byte code
		*(ULONG*)&ShellCodeTemplate[OLD_FUNC_OFFSET] = CALC_JMP_OFFSET(
			(char*)OldFunc + InstLen,
			&info.ShellCode[OLD_JMP_FUNC_OFFSET]
		);

		//Copy the pre-costructed shellcode into buffer
		memcpy(info.ShellCode, ShellCodeTemplate, sizeof(ShellCodeTemplate));

		//Modify original byte code and jmp to the shellcode
		switch (InstLen)
		{
		case 5: //Jmp xxxx  , 0xE9 XX XX XX XX
			*(PLONG)(&E9JmpCode[1]) = CALC_JMP_OFFSET(info.ShellCode, OldFunc);
			RtlCopyMemory(OldFunc, E9JmpCode, InstLen);
			break;
		case 6: //Push, ret , 0x66 xx xx xx xx , C3
			*(PLONG)(&PushRetJmpCode[1]) = (LONG)((char*)info.ShellCode);
			RtlCopyMemory(OldFunc, PushRetJmpCode, InstLen);
			break;
		default:
			break;
		}

		//Use for unhook
		info.OldByteLen = InstLen;
		info.NewFunc = NewFunc;
		info.OldFunc = OldFunc;

		//return the info
		memcpy(Info, &info, sizeof(HOOKINFO));

	} while (FALSE);
	if (ret) {
		return ret;
	}

	if (oldProtect)
	{
		VirtualProtect(Info->OldFunc, 0x1000, oldProtect, &oldProtect);
	}

	if (info.ShellCode)
	{
		VirtualFree(info.ShellCode, 0, MEM_RELEASE);
		info.ShellCode = nullptr;
	}
	
	return ret;
}