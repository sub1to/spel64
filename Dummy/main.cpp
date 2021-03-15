#include "stdafx.h"
#include <codecvt>

std::string w2s(std::wstring utf16_string)
{
	static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> convert;
	return convert.to_bytes(utf16_string).c_str();
}

std::wstring s2w(std::string utf8_string)
{
	static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(utf8_string);
}

DWORD __stdcall mainThread(LPVOID lpParam)
{
	//*
	__try{
		wprintf_s(L"segfaulting\n");
		int* a = (int*) 123;
		*a = 1337;
	} __except(EXCEPTION_EXECUTE_HANDLER){
		wprintf_s(L"__except\n");
	}
	//*/

	wprintf_s(L"mainthread done\n");

	return S_OK;
}

int __stdcall DllMain
(
	HMODULE	hModule,
	DWORD	fdwReason,
	LPVOID	lpReserved
)
{
	AllocConsole();
	FILE* pCout;
	freopen_s(&pCout, "conin$", "r", stdin);
	freopen_s(&pCout, "conout$", "w", stdout);
	freopen_s(&pCout, "conout$", "w", stderr);

	printf_s("lpReserved: %lld\n", (uint64_t) lpReserved);
	//*
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		wprintf_s(&s2w("Hello from Dummy.dll DLL_PROCESS_ATTACH\n")[0]);

		CreateThread
		(
			nullptr,
			0,
			mainThread,
			nullptr,
			0,
			nullptr
		);

		break;
	case DLL_THREAD_ATTACH:
		wprintf_s(&s2w("Hello from Dummy.dll DLL_THREAD_ATTACH\n")[0]);
		break;
	case DLL_THREAD_DETACH:
		wprintf_s(&s2w("Hello from Dummy.dll DLL_THREAD_DETACH\n")[0]);
		break;
	case DLL_PROCESS_DETACH:
		wprintf_s(&s2w("Hello from Dummy.dll DLL_PROCESS_DETACH\n")[0]);
		break;
	}
	//*/
	return true;
}