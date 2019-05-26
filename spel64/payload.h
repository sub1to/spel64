#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#define PE_INIT_SIZE			(reinterpret_cast<unsigned long long>(&Payload::pe_init_end) - reinterpret_cast<unsigned long long>(&Payload::pe_init_context))
#define THREAD_HIJACKER_SIZE	(reinterpret_cast<unsigned long long>(&Payload::thread_hijacker_end) - reinterpret_cast<unsigned long long>(&Payload::thread_hijacker_context))
#define PE_FREE_SIZE			(reinterpret_cast<unsigned long long>(&Payload::pe_free_end) - reinterpret_cast<unsigned long long>(&Payload::pe_free_context))

namespace Payload
{
	typedef struct PEIC	//PE_INIT_CONTEXT
	{
		const void*		pModule;
		const void*		pEntryPoint;
		const void*		pImportDescriptorTable;
		const void*		pLoadLibraryA;
		const void*		pGetProcAddress;
	} PEIC;

	typedef struct THC	//THREAD_HIJACKER_CONTEXT
	{
		const void*		pEntryPoint;
		const void*		pReturnAddress;
	} THC;

	typedef struct PEFC	//PE_FREE_CONTEXT
	{
		const void*		pModule;
		const void*		pEntryPoint;
	} PEFC;

	extern "C" PEIC		pe_init_context;
	extern "C" void		pe_init();	
	extern "C" void		pe_init_end();

	extern "C" THC		thread_hijacker_context;
	extern "C" void		thread_hijacker();
	extern "C" void		thread_hijacker_end();

	extern "C" PEIC		pe_free_context;
	extern "C" void		pe_free();	
	extern "C" void		pe_free_end();
}

#endif //_PAYLOAD_H_