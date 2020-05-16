#pragma once

#include "Windows.h"
#define HOOK_INST_LEN_MISTMATCH	 0x1
#define HOOK_INST_NON_WRITEABLE  0x2
#define HOOK_INST_MEM_NOT_ENOUGH 0x3

#pragma pack(push, 1)
typedef struct INLINE_HOOK_INFO
{
	void* OldFunc;
	int   OldByteLen;
	void* NewFunc;
	char* ShellCode;
}HOOKINFO, *PHOOKINFO;
#pragma pack(pop)

BOOL InlineUnHook(
	_In_ HOOKINFO* Info
);

int InlineHook(
	 void*		OldFunc,
	 void*		NewFunc,
	 ULONG		HookSize,
	 HOOKINFO* Info
);

int  EATHookTest();

int  IATHookTest();

void VEHHookDemo();