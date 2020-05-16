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

int main()
{
	HOOKINFO g_HookInfo = { 0 };

	printf("-------------------------------- Original Function Output --------------------------------\r\n");
	TestDemo();
	InlineHook(TestDemo, HookTestDemo, 5,  &g_HookInfo);
	
	printf("-------------------------------- Inline Hook Function Output -------------------------------- \r\n");
	TestDemo();
	InlineUnHook(&g_HookInfo);
	printf("-------------------------------- Inline UnHook Function Output --------------------------------\r\n");
	TestDemo();

	printf("-------------------------------- EXport Table Hook Demo -------------------------------- \r\n");
	EATHookTest();

	printf("-------------------------------- Import Table Hook Demo -------------------------------- \r\n");
	IATHookTest();

	VEHHookDemo();

	getchar();

    return 0;
}

