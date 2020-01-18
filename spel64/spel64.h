#ifndef _SPEL64_LOADER_H_
#define _SPEL64_LOADER_H_

#include <Windows.h>
#include <fstream>

#ifdef LoadLibrary
#undef LoadLibrary
#endif //LoadLibrary

#ifdef LoadLibraryEx
#undef LoadLibraryEx
#endif //LoadLibraryEx

#ifdef _SPEL64_LOADER_EXPORT_
#define SPEL64API __declspec(dllexport)
#else
#define SPEL64API __declspec(dllimport)
#endif

namespace spel64
{
	enum eSpelResponse : unsigned long long
	{
		SPEL64_R_OK											= 0,
		SPEL64_R_FAILED_TO_READ_FILE						= 1,
		SPEL64_R_FAILED_TO_ALLOCATE_LOCAL_MEMORY			= 2,
		SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY			= 3,
		SPEL64_R_INVALID_PE_FORMAT							= 4,
		SPEL64_R_FAILED_TO_CREATE_THREAD					= 5,
		SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY				= 6,
		SPEL64_R_FAILED_TO_FREE_REMOTE_MEMORY				= 7,
		SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY				= 8,
		SPEL64_R_FAILED_TO_CREATE_SNAPSHOT					= 9,
		SPEL64_R_FAILED_TO_FIND_THREAD						= 10,
		SPEL64_R_FAILED_TO_OPEN_THREAD						= 11,
		SPEL64_R_FAILED_TO_SUSPEND_THREAD					= 12,
		SPEL64_R_FAILED_TO_GET_THREAD_CONTEXT				= 13,
		SPEL64_R_FAILED_TO_SET_THREAD_CONTEXT				= 14,
		SPEL64_R_FAILED_TO_RESUME_THREAD,
	};

	enum eThreadFlags : unsigned long long
	{
		THREADFLAG_NONE		= 1 >> 1,
		THREADFLAG_SYNC		= 1 << 0,	// Synchronous execution 
	};

	enum eSpel64Flags : unsigned long long
	{
		SPEL64FLAG_NONE					= 1 >> 1,
		SPEL64FLAG_NO_PE_HEADER			= 1 << 0,		// Hide PE header
		SPEL64FLAG_HIJACK_THREAD		= 1 << 1,		// Hijack a thread instead of creating a new thread (to execute the entry point)
		SPEL64FLAG_NO_LDR				= 1 << 2,		// Not implemented
	};

	#define SPEL64_FLAGS_DEFAULT	spel64::SPEL64FLAG_NO_PE_HEADER | spel64::SPEL64FLAG_HIJACK_THREAD | spel64::SPEL64FLAG_NO_LDR

	/**
	*	Load a dynamic library in the current process
	*
	*	@param	const char*		szPath			Path to dynamic library
	*	@param	HMODULE*		pOut			Pointer to HMODULE out
	*	@param	const uint64_t	ullFlags		eSpel64Flags
	*
	*	@return	eSpelResponse
	*/
	extern "C" eSpelResponse	SPEL64API	load_library(const char* szPath, HMODULE* pOut, const uint64_t ullFlags = SPEL64_FLAGS_DEFAULT);

	/**
	*	Free a dynamic library in the current process
	*	Only use this on libraries that were also loaded by spel64
	*	Will not unload import dependancies
	*
	*	@param	const HMODULE	hModule			Library to free
	*	@param	const uint64_t	ullFlags		eSpel64Flags
	*
	*	@return	eSpelResponse
	*/
	extern "C" eSpelResponse	SPEL64API	free_library(const HMODULE hModule, const uint64_t ullFlags = SPEL64_FLAGS_DEFAULT);

	/**
	*	Load a dynamic library in a remote process
	*
	*	@param	const HANDLE	hProc			Handle to the process
	*	@param	const char*		szPath			Path to dynamic library
	*	@param	HMODULE*		pOut			Pointer to HMODULE out
	*	@param	const uint64_t	ullFlags		eSpel64Flags
	*
	*	@return	eSpelResponse
	*/
	extern "C" eSpelResponse	SPEL64API	load_library_ex(const HANDLE hProc, const char* szPath, HMODULE* pOut, const uint64_t ullFlags = SPEL64_FLAGS_DEFAULT, const uint64_t lpReserved = 0);

	/**
	*	Free a dynamic library in a remote process
	*	Only use this on libraries that were also loaded by spel64
	*	Will not unload import dependancies
	*
	*	@param	const HANDLE	hProc			Handle to the process
	*	@param	const HMODULE	hModule			Library to free
	*	@param	const uint64_t	ullFlags		eSpel64Flags
	*
	*	@return	eSpelResponse
	*/
	extern "C" eSpelResponse	SPEL64API	free_library_ex(const HANDLE hProc, const HMODULE hModule, const uint64_t ullFlags = SPEL64_FLAGS_DEFAULT);

	/**
	*	Hijack the first (encountered) thread in a process
	*	If pOut is not nullptr, you have to close the handle after you're done with it.
	*
	*	@param	const HANDLE	hProc			Handle to the process
	*	@param	const void*		pEntryPoint		Address of the (remote) entry point
	*	@param	const uint64_t	ullFlags		eThreadFlags
	*	@param	HANDLE*			pOut			Pointer to HANDLE for the hijacked thread
	*
	*	@return	eSpelResponse
	*/
	extern "C" eSpelResponse	SPEL64API	hijack_first_thread(const HANDLE hProc, const void* pEntryPoint, const uint64_t ullFlags, HANDLE* pOut);

	/**
	*	Hijack a thread in a process
	*
	*	@param	const HANDLE	hProc			Handle to the process
	*	@param	const void*		pEntryPoint		Address of the (remote) entry point
	*	@param	const uint64_t	ullFlags		eThreadFlags
	*
	*	@return	eSpelResponse
	*/
	extern "C" eSpelResponse	SPEL64API	hijack_thread(const HANDLE hProc, const HANDLE hThread, const void* pEntryPoint, const uint64_t ullFlags);
};


#endif //_SPEL64_LOADER_H_