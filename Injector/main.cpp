#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <fstream>
#include "spel64.h"
#include <tlhelp32.h>

int main(int argc, char* argv)
{
	HANDLE					hProc;
	HMODULE					hModule;
	PROCESSENTRY32			entry;
	HANDLE					snapshot;
	spel64::eSpelResponse	response;
	
	entry.dwSize = sizeof(PROCESSENTRY32);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if(Process32First(snapshot, &entry) == TRUE)
	{
		while(Process32Next(snapshot, &entry) == TRUE)
		{
			if(_stricmp(entry.szExeFile, "notepad.exe") == 0)
			{  
				hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				break;
			}
		}
	}
	CloseHandle(snapshot);

	printf_s("Loading library...\n");

	//response		= spel64::load_library_ex(hProc, "V:\\projects\\spel64\\Release\\Dummy.dll", &hModule);
	response		= spel64::load_library_ex(hProc, "Dummy.dll", &hModule, 0, 1234);

	if(response != spel64::SPEL64_R_OK)
	{
		printf_s("Failed to load module %lld\n", response);
		printf_s("GetLastError %d\n", GetLastError());
	}

	printf_s("PELoader::LoadLibrary: %p\n", hModule);

	printf_s("Press any key to continue\n");
	_getch();

	printf_s("Freeing library...\n");

	spel64::free_library_ex(hProc, hModule);
	//spel64::FreeLibrary(hModule);

	printf_s("Press any key to close\n");
	_getch();

	return S_OK;
}