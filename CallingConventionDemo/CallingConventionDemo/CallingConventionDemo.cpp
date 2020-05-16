// CallingConventionDemo.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "stdlib.h"
int __stdcall StdCall(int o) {
	return (o * 4 + 0x2342354a);
}

int __cdecl CdeclCall(int o) {
	return (o * 1921291 + 0x32213129f);
}

int __fastcall FastCall(int o) {
	return (o * 90231290 + 0x12893012);
}

class ThisCallTest{
public :
	ThisCallTest() {

	}

	int ThisCallDemo(int o) {
		return (o * 1921291 + 0x32213129f);
	}
};

int main()
{
	ThisCallTest* test = new ThisCallTest();

	StdCall(0x12312312);
	CdeclCall(0x32432542);
	FastCall(0x2e312322);
	test->ThisCallDemo(0x21312231);
	system("pause");
    return 0;
}

