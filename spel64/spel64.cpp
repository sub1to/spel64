#define _SPEL64_LOADER_EXPORT_
#include "spel64.h"
#include "_spel64.h"
#include "memory.h"
#include "payload.h"
#include <TlHelp32.h>

//#define DEBUG_OUTPUT

#ifdef DEBUG_OUTPUT
#define DEBUG_MSG(x, ...) printf_s(x, __VA_ARGS__)
#else
#define DEBUG_MSG(x, ...)
#endif //DEBUG_OUTPUT

#define FREE_LIB_SIGNATURE 0xD15EA5E1FEC7ED

typedef struct _free_lib_header
{
	unsigned long long	ullSignature	= FREE_LIB_SIGNATURE;
	unsigned long long	pEntryPoint		= 0;
} FREE_LIB_HEADER, *PFREE_LIB_HEADER;

typedef int (__stdcall* fpDllMain)(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved);

namespace spel64
{
	__declspec(noinline) const char*		read_file(const char* szPath, size_t* pSizeOut = nullptr)
	{
		char*				ret;
		std::ifstream		file;
		size_t				ullSize;

		ret			= nullptr;

		file.open(szPath, std::ios::in|std::ios::binary|std::ios::ate);

		if(!file.is_open())
			goto LABEL_RETURN;

		file.seekg(0, file.end);
		ullSize		= file.tellg();
		file.seekg(0, file.beg);

		if(pSizeOut != nullptr)
			*pSizeOut	= ullSize;

		ret		= new char[ullSize];

		file.read((char*) ret, ullSize);
		file.close();

	LABEL_RETURN:
		return ret;
	}

	__declspec(noinline) eSpelResponse	load_library_ex(HANDLE hProc, const char* szPath, HMODULE* pOut, const uint64_t ullFlags, const uint64_t lpReserved)
	{
		eSpelResponse					ret;
		char*							pLocalBuffer;
		char*							pShellCode;
		char*							pRemoteBuffer;
		size_t							ullBufferSize;		
		IMAGE_NT_HEADERS*				pNt;
		const char*						pFile;
		Payload::PEIC					PEIC	= {};
	
		pRemoteBuffer		= nullptr;
		pShellCode			= nullptr;
		pLocalBuffer		= nullptr;
		pFile				= (ullFlags & SPEL64FLAG_FROM_MEMORY) ? szPath : read_file(szPath);

		if(pFile == nullptr)
		{
			ret		= SPEL64_R_FAILED_TO_READ_FILE;
			goto LABEL_RETURN;
		}

		ret		= get_nt_header(pFile, &pNt);

		if(ret != SPEL64_R_OK)
			goto LABEL_RETURN;

		ullBufferSize	= pNt->OptionalHeader.SizeOfImage;
		pLocalBuffer	= reinterpret_cast<char*>(VirtualAlloc(nullptr, ullBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		DEBUG_MSG("ullBufferSize %llx\n", ullBufferSize);
		DEBUG_MSG("pLocalBuffer %p\n", pLocalBuffer);
		
		if(pLocalBuffer == nullptr)
		{
			ret		= SPEL64_R_FAILED_TO_ALLOCATE_LOCAL_MEMORY;
			goto LABEL_RETURN;
		}

		pRemoteBuffer	= reinterpret_cast<char*>(VirtualAllocEx(hProc, nullptr, ullBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		DEBUG_MSG("pRemoteBuffer %p\n", pRemoteBuffer);

		if(pRemoteBuffer == nullptr)
		{
			ret		= SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		DEBUG_MSG("Mapping image into local memory\n");

		ret		= map_image(pLocalBuffer, pFile, pRemoteBuffer, ullFlags);

		if(ret != SPEL64_R_OK)
			goto LABEL_RETURN;

		DEBUG_MSG("Fixing Base Relocations\n");

		ret		= init_base_relocations(pNt, pLocalBuffer, pRemoteBuffer);	

		if(ret != SPEL64_R_OK)
			goto LABEL_RETURN;

		if(!WriteProcessMemory(hProc, pRemoteBuffer, pLocalBuffer, ullBufferSize, nullptr))
		{
			ret		= SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		PEIC.pModule					= pRemoteBuffer;
		PEIC.pEntryPoint				= pRemoteBuffer + pNt->OptionalHeader.AddressOfEntryPoint;
		PEIC.pImportDescriptorTable		= reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pRemoteBuffer + reinterpret_cast<IMAGE_DATA_DIRECTORY*>(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);
		PEIC.pLoadLibraryA				= LoadLibraryA;
		PEIC.pGetProcAddress			= GetProcAddress;
		PEIC.pRtlAddFunctionTable		= RtlAddFunctionTable;
		PEIC.lpReserved					= lpReserved;
		pShellCode						= reinterpret_cast<char*>(VirtualAllocEx(hProc, nullptr, PE_INIT_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if(pShellCode == nullptr)
		{
			ret		= SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		if(	!WriteProcessMemory(hProc, pShellCode, &Payload::pe_init_context, PE_INIT_SIZE, nullptr)
		||	!WriteProcessMemory(hProc, pShellCode, &PEIC, sizeof(PEIC), nullptr))
		{
			ret		= SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		if(ullFlags & SPEL64FLAG_HIJACK_THREAD)
			ret	= hijack_first_thread(hProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode + sizeof(PEIC)), THREADFLAG_SYNC, nullptr);
		else
			ret	= create_thread_ex(hProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode + sizeof(PEIC)), THREADFLAG_SYNC, nullptr);

		DEBUG_MSG("Finished loading library %d\n", ret);

	LABEL_RETURN:
		if(pShellCode && !VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE) && ret == SPEL64_R_OK)
			ret		= SPEL64_R_FAILED_TO_FREE_REMOTE_MEMORY;

		if(!(ullFlags & SPEL64FLAG_FROM_MEMORY) && pFile != nullptr)
			delete[] pFile;

		if(pLocalBuffer != nullptr)
			VirtualFree(pLocalBuffer, 0, MEM_RELEASE);

		if(pOut != nullptr)
			*pOut	= reinterpret_cast<HMODULE>(pRemoteBuffer);

		DEBUG_MSG("load_library_ex ret\n");
			
		return ret;
	}

	__declspec(noinline) eSpelResponse free_library_ex(const HANDLE hProc, const HMODULE hModule, const uint64_t ullFlags)
	{
		eSpelResponse	ret;
		fpDllMain		pEntryPoint;
		uint64_t		ullSig;
		char*			pShellCode;
		Payload::PEFC	PEFC;

		ret			= SPEL64_R_OK;

		if(!ReadProcessMemory(hProc, hModule, &ullSig, sizeof(uint64_t), nullptr))
		{
			ret		= SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		if(ullSig == FREE_LIB_SIGNATURE)
		{
			if(!ReadProcessMemory(hProc, reinterpret_cast<char*>(hModule) + offsetof(FREE_LIB_HEADER, pEntryPoint), &pEntryPoint, sizeof(fpDllMain), nullptr))
			{
				ret		= SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY;
				goto LABEL_RETURN;
			}
		}
		else if((ullSig & 0xFFFF) == IMAGE_DOS_SIGNATURE)
		{
			IMAGE_DOS_HEADER	dos;
			IMAGE_NT_HEADERS	nt;

			if(!ReadProcessMemory(hProc, reinterpret_cast<char*>(hModule), &dos, sizeof(IMAGE_DOS_HEADER), nullptr))
			{
				ret		= SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY;
				goto LABEL_RETURN;
			}

			if(!ReadProcessMemory(hProc, reinterpret_cast<char*>(hModule) + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), nullptr))
			{
				ret		= SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY;
				goto LABEL_RETURN;
			}

			pEntryPoint		= reinterpret_cast<fpDllMain>(reinterpret_cast<char*>(hModule) + nt.OptionalHeader.AddressOfEntryPoint);
		}
		else
		{
			ret		= SPEL64_R_INVALID_PE_FORMAT;
			goto LABEL_RETURN;
		}

		PEFC.pEntryPoint				= pEntryPoint;
		PEFC.pModule					= hModule;
		PEFC.pRtlDeleteFunctionTable	= RtlDeleteFunctionTable;
		pShellCode						= reinterpret_cast<char*>(VirtualAllocEx(hProc, nullptr, PE_FREE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if(pShellCode == nullptr)
		{
			ret		= SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		if(	!WriteProcessMemory(hProc, pShellCode, &Payload::pe_free_context, PE_FREE_SIZE, nullptr)
		||	!WriteProcessMemory(hProc, pShellCode, &PEFC, sizeof(PEFC), nullptr))
		{
			ret		= SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		if(ullFlags & SPEL64FLAG_HIJACK_THREAD)
			hijack_first_thread(hProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode + sizeof(PEFC)), THREADFLAG_SYNC, nullptr);
		else
			create_thread_ex(hProc, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode + sizeof(PEFC)), THREADFLAG_SYNC, nullptr);

		if(	!VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE)
		||	!VirtualFreeEx(hProc, hModule, 0, MEM_RELEASE))
		{
			ret		= SPEL64_R_FAILED_TO_FREE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

	LABEL_RETURN:
		return ret;
	}

	__declspec(noinline) eSpelResponse	hijack_first_thread(const HANDLE hProc, const void* pEntryPoint, const uint64_t ullFlags, HANDLE* pOut)
	{
		eSpelResponse	ret;
		HANDLE			hHandle;
		THREADENTRY32	te32;
		uint32_t		ulProcId;
		BOOL			ulResult;

		ret			= SPEL64_R_OK;
		hHandle		= CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

		if(hHandle == INVALID_HANDLE_VALUE)
		{
			ret		= SPEL64_R_FAILED_TO_CREATE_SNAPSHOT;
			goto LABEL_RETURN;
		}

		te32.dwSize	= sizeof(te32);
		ulProcId	= GetProcessId(hProc);

		for(ulResult = Thread32First(hHandle, &te32); ulResult; ulResult = Thread32Next(hHandle, &te32))
		{
			if(te32.th32OwnerProcessID != ulProcId)
				continue;
		
			break;
		}

		CloseHandle(hHandle);

		if(!ulResult)
		{
			ret		= SPEL64_R_FAILED_TO_FIND_THREAD;
			CloseHandle(hHandle);
			goto LABEL_RETURN;
		}

		DEBUG_MSG("Found thread to hijack: 0x%x\n", te32.th32ThreadID);

		hHandle		= OpenThread(THREAD_ALL_ACCESS, false, te32.th32ThreadID);

		if(hHandle == INVALID_HANDLE_VALUE)
		{
			ret		= SPEL64_R_FAILED_TO_OPEN_THREAD;
			CloseHandle(hHandle);
			goto LABEL_RETURN;
		}

		ret			= hijack_thread(hProc, hHandle, pEntryPoint, ullFlags);

		if(ret != SPEL64_R_OK || pOut == nullptr)
			CloseHandle(hHandle);
		else
			*pOut	= hHandle;

	LABEL_RETURN:	
		return ret;
	}

	__declspec(noinline) eSpelResponse	hijack_thread(const HANDLE hProc, const HANDLE hThread, const void* pEntryPoint, const uint64_t ullFlags)
	{
		eSpelResponse	ret;
		CONTEXT			context;
		char*			pThreadHijacker;
		Payload::THC	THC;

		ret				= SPEL64_R_OK;
		pThreadHijacker	= nullptr;

		if(SuspendThread(hThread) == 0xFFFFFFFF)
		{
			ret		= SPEL64_R_FAILED_TO_SUSPEND_THREAD;
			goto LABEL_RETURN;
		}

		context.ContextFlags	= CONTEXT_FULL;

		if(!GetThreadContext(hThread, &context))
		{
			ret		= SPEL64_R_FAILED_TO_GET_THREAD_CONTEXT;
			ResumeThread(hThread);
			goto LABEL_RETURN;
		}

		pThreadHijacker		= reinterpret_cast<char*>(VirtualAllocEx(hProc, nullptr, THREAD_HIJACKER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if(pThreadHijacker == nullptr)
		{
			ret		= SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY;
			ResumeThread(hThread);
			goto LABEL_RETURN;
		}

		THC.pEntryPoint		= pEntryPoint;
		THC.pReturnAddress	= reinterpret_cast<const void*>(context.Rip);

		if(	!WriteProcessMemory(hProc, pThreadHijacker, &Payload::thread_hijacker_context, THREAD_HIJACKER_SIZE, nullptr)
		||	!WriteProcessMemory(hProc, pThreadHijacker, &THC, sizeof(THC), nullptr))
		{
			ret		= SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY;
			goto LABEL_RETURN;
		}

		context.Rip		= reinterpret_cast<uint64_t>(pThreadHijacker + sizeof(pEntryPoint) + sizeof(context.Rip));

		if(!SetThreadContext(hThread, &context))
		{
			ret		= SPEL64_R_FAILED_TO_SET_THREAD_CONTEXT;
			ResumeThread(hThread);
			goto LABEL_RETURN;
		}

		if(ResumeThread(hThread) == 0xFFFFFFFF)
		{
			ret		= SPEL64_R_FAILED_TO_RESUME_THREAD;
			goto LABEL_RETURN;
		}

		if(ullFlags & THREADFLAG_SYNC)
		{
			DEBUG_MSG("Waiting for thread hijacker to finish\n");

			for(;; Sleep(1))
			{
				uint64_t	ullStatus;

				if(!ReadProcessMemory(hProc, pThreadHijacker, &ullStatus, sizeof(ullStatus), nullptr) || !ullStatus)
					break;
			}

			Sleep(1);

			DEBUG_MSG("Thread hijacker has finished\n");
		}

	LABEL_RETURN:
		if(pThreadHijacker && !VirtualFreeEx(hProc, pThreadHijacker, 0, MEM_RELEASE))
			ret		= SPEL64_R_FAILED_TO_FREE_REMOTE_MEMORY;

		return ret;
	}

};


