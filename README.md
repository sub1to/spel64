
# SPEL64
C++ PE loader library made to manual map a dynamic library into a remote process. Written in C++ and MASM.
  
## Getting Started  
These instructions will get you up and running. Please check the non-existent documentation if anything is still unclear.  
  
### Prerequisites  
- Knowledge of C++
   
### Installing  
- `git clone https://github.com/sub1to/spel64.git`  
- Compile
- Copy
- Pasta
   
### Usage  
```cpp
spel64::load_library_ex(hProc, "Dummy.dll", &hModule, SPEL64_FLAGS_DEFAULT);
spel64::free_library_ex(hProc, hModule, SPEL64FLAG_HIJACK_THREAD);
```

You might need to compile the loaded library with `/Zc:threadSafeInit-` to make sure static variables are not initialized
in a threadsafe manner, because TLS initialization is not implemented. [MSDN](https://docs.microsoft.com/en-us/cpp/build/reference/zc-threadsafeinit-thread-safe-local-static-initialization?view=vs-2019)

#### Response Codes

| Val | Name                                          | Description                           |
|-----|-----------------------------------------------|---------------------------------------|
| 0   | SPEL64_R_OK                                   | Success                               |
| 1   | SPEL64_R_FAILED_TO_READ_FILE                  | Could not open the library file       |
| 2   | SPEL64_R_FAILED_TO_ALLOCATE_LOCAL_MEMORY      | VirtualAlloc failed                   |
| 3   | SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY     | VirtualAllocEx failed                 |
| 4   | SPEL64_R_INVALID_PE_FORMAT                    | Signature mismatch                    |
| 5   | SPEL64_R_FAILED_TO_CREATE_THREAD              | CreateRemoteThread failed             |
| 6   | SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY        | WriteProcessMemory failed             |
| 7   | SPEL64_R_FAILED_TO_FREE_REMOTE_MEMORY         | VirtualFreeEx failed                  |
| 8   | SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY         | ReadProcessMemory failed              |
| 9   | SPEL64_R_FAILED_TO_CREATE_SNAPSHOT            | CreateToolhelp32Snapshot failed       |
| 10  | SPEL64_R_FAILED_TO_FIND_THREAD                | Did not find a valid thread to hijack |
| 11  | SPEL64_R_FAILED_TO_OPEN_THREAD                | OpenThread failed                     |
| 12  | SPEL64_R_FAILED_TO_SUSPEND_THREAD             | SuspendThread failed                  |
| 13  | SPEL64_R_FAILED_TO_GET_THREAD_CONTEXT         | GetThreadContext failed               |
| 14  | SPEL64_R_FAILED_TO_SET_THREAD_CONTEXT         | SetThreadContext failed               |

If the response incidicates a WinAPI call failure (like SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY) you can call GetLastError
to get more details about the WinAPI error.

#### Flags
| Flag                              | Description                           |
|-----------------------------------|---------------------------------------|
| SPEL64FLAG_NO_PE_HEADER           | Hide PE header                        |
| SPEL64FLAG_HIJACK_THREAD          | Hijack a thread to execute entrypoint |

`SPEL64FLAG_NO_PE_HEADER` will cause SEH not to work, because the module will not have access to the data directory inside the NT optional header.
  
## Examples  
  
#### Injector example
An example injector and dummy library are included with the project.
```cpp
#include "spel64.h"
#pragma comment(lib, "spel64.lib")

int main(int argc, char* argv)
{
	HANDLE					hProc;
	HMODULE					hModule;
	PROCESSENTRY32			entry;
	HANDLE					snapshot;
	spel64::eSpelResponse	response;
	
	entry.dwSize = sizeof(PROCESSENTRY32);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, "notepad.exe") == 0)
			{  
				hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				break;
			}
		}
	}
	CloseHandle(snapshot);

	printf_s("Loading library...\n");
	
	response		= spel64::load_library_ex(hProc, "Dummy.dll", &hModule);

	if(response != spel64::SPEL64_R_OK)
	{
		printf_s("Failed to load module\n");
	}

	printf_s("Loaded library...\n");

	return S_OK;
} 
```
  
## Authors  
- **sub1to** - *Initial work* - [sub1to](https://github.com/sub1to)  
  
See also the list of [contributors](https://github.com/sub1to/spel64/contributors) who participated in this project.  
  
## License  
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details  
  
## TODO  
- Link to LDR
- TLS initialization
