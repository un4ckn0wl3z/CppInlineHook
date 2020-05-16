#include "stdafx.h"
#include "Windows.h"
#include "stdio.h"
char g_Buf[0x1000] = { 0 };

LONG NTAPI VectoredExceptionHandler(
	 EXCEPTION_POINTERS* ExceptionInfo
) 
{
	ULONG oldProtect = 0;
	VirtualProtect(g_Buf, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
	printf("x \r\n");
	return EXCEPTION_EXECUTE_HANDLER;
}

void VEHHookDemo() {
	ULONG oldProtect = 0;
	VirtualProtect(g_Buf, 0x1000, PAGE_NOACCESS, &oldProtect);
	AddVectoredExceptionHandler(TRUE, VectoredExceptionHandler);
	g_Buf[0] = 1;
}
