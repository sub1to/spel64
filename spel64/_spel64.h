#ifndef __SPEL64_LOADER_H_
#define __SPEL64_LOADER_H_

//Private header for non-exported symbols

namespace spel64
{
	extern "C" eSpelResponse	map_image(char* pDest, char* pSource, char* pRemote, uint64_t ullFlags);
	extern "C" eSpelResponse	init_base_relocations(const IMAGE_NT_HEADERS64* pNt, char* pDest, char* pRemoteBuffer);
	extern "C" eSpelResponse	get_nt_header(const void* pDos, IMAGE_NT_HEADERS64** pOut);
	extern "C" eSpelResponse	create_thread_ex(const HANDLE hProc, const LPTHREAD_START_ROUTINE pEntryPoint, const uint64_t ullFlags, HANDLE* pOut);
};


#endif //__SPEL64_LOADER_H_