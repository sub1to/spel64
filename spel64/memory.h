#ifndef _MEMORY_H_
#define _MEMORY_H_

extern "C" void*	_memcpy(void* pDest, const void* pSource, const unsigned long long ullSize);
extern "C" void*	_zeromem(void* pDest, const unsigned long long ullSize);
extern "C" void*	_memset(void* pDest, const char val, const unsigned long long ullSize);


#endif //_MEMORY_H_
