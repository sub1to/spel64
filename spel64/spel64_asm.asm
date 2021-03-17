INCLUDE spel64.inc

.DATA

.CODE
	PUBLIC load_library
	PUBLIC free_library
	PUBLIC create_thread_ex
	PUBLIC map_image

	; @param	char*			Path to file
	; @param	HMODULE*		Out
	; @param	uint64_t		flags
	; @return	eSpelResponse
	load_library PROC EXPORT

		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 40h]

		mov [rsp + 20h], rcx
		mov [rsp + 28h], rdx
		mov [rsp + 30h], r8
		call GetCurrentProcess
		
		and rax, rax
		jz label_return

		mov rcx, rax
		mov rdx, [rsp + 20h]
		mov r8, [rsp + 28h]
		mov r9, [rsp + 30h]
		call load_library_ex
		
	label_return:
		lea rsp, [rbp]
		pop rbp
		ret

	load_library ENDP


	; @param	HMODULE			Module handle
	; @param	uint64_t		flags
	; @return	eSpelResponse
	free_library PROC EXPORT

		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 30h]

		mov [rsp + 20h], rcx
		mov [rsp + 28h], rdx
		call GetCurrentProcess
		
		and rax, rax
		jz label_return

		mov rcx, rax
		mov rdx, [rsp + 20h]
		mov r8, [rsp + 28h]
		call free_library_ex
		
	label_return:
		lea rsp, [rbp]
		pop rbp
		ret

	free_library ENDP


	; @param	HANDLE			Process handle
	; @param	void*			Entry point
	; @param	uint64_t		Thread flags
	; @param	HANDLE*			Out
	; @return	eSpelResponse
	create_thread_ex PROC
		
		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 50h]

		; WinAPI CreateRemoteThread
		mov [rsp + 38h], r8
		mov [rsp + 40h], r9
		mov r9, rdx						; pEntryPoint
		xor rdx, rdx
		xor r8, r8
		mov qword ptr [rsp + 20h], r8
		mov qword ptr [rsp + 28h], r8
		mov qword ptr [rsp + 30h], r8
		call CreateRemoteThread

		and rax, rax
		jnz label_sync_test

		; Failed to create remote thread
		mov rax, SPEL64_R_FAILED_TO_CREATE_THREAD
		jmp label_return

	label_sync_test:
		mov [rsp + 20h], rax
		mov r8, [rsp + 38h]
		and r8, THREADFLAG_SYNC
		jz label_out					; Synchronous execution flag not set

		; Synchronous execution	
		mov rcx, rax
		mov rdx, INFINITE
		call WaitForSingleObject

	label_out:
		xor rax, rax					; SPEL64_R_OK
		xor rcx, rcx
		cmp rcx, [rsp + 40h]
		jz label_return

		mov r9, [rsp + 40h]
		mov rcx, [rsp + 20h]
		mov [r9], rcx

	label_return:
		lea rsp, [rbp]
		pop rbp
		ret

	create_thread_ex ENDP

	; @param	IMAGE_DOS_HEADER*			Ptr to PE image
	; @param	IMAGE_NT_HEADERS64**		Out
	; @return	Response Code
	get_nt_header PROC

		push rbp
		lea rbp, [rsp]

		mov ax, IMAGE_DOS_SIGNATURE
		cmp ax, word ptr [rcx]
		jnz label_invalid_format

		xor rax, rax
		mov eax, IMAGE_DOS_HEADER.e_lfanew[rcx]
		lea rax, [rcx + rax]					; IMAGE_NT_HEADERS64

		cmp IMAGE_NT_HEADERS64.Signature[rax], IMAGE_NT_SIGNATURE
		jnz label_invalid_format

		mov [rdx], rax
		xor rax, rax
		jmp label_return

	label_invalid_format:
		mov rax, SPEL64_R_INVALID_PE_FORMAT
		
	label_return:
		pop rbp
		ret

	get_nt_header ENDP

	; @param	char*		Dest buffer
	; @param	void*		Entry point
	; @return	void
	create_free_lib_header PROC

		mov rax, FREE_LIB_SIGNATURE
		mov FREE_LIB_HEADER.ullSignature[rcx], rax
		mov FREE_LIB_HEADER.pEntryPoint[rcx], rdx
		ret

	create_free_lib_header ENDP

	; @param	char*		Dest buffer
	; @param	char*		Src buffer
	; @param	char*		Remote Buffer
	; @param	uint64_t	Flags
	; @return	eSpelResponse
	map_image PROC

		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 50h]
		mov [rbp - 08h], rdi
		mov [rbp - 10h], rsi
		mov [rbp - 18h], rbx
		mov [rbp - 20h], r12
		mov [rbp - 28h], r13

		mov rdi, rcx
		mov rsi, rdx
		mov rbx, r8

		mov rcx, rdx
		lea rdx, [rbp - 30h]
		call get_nt_header

		and rax, rax
		jnz label_return							; Failed to get nt header pointer

		mov r12, [rbp - 30h]
		mov rcx, rdi
		mov rdx, IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage
		call _zeromem

		test r9, SPEL64FLAG_NO_PE_HEADER
		jnz label_custom_header

		; Place normal PE header
		mov rcx, rdi
		mov rdx, rsi
		xor r8, r8
		mov r8d, IMAGE_NT_HEADERS64.OptionalHeader.SizeOfHeaders[r12]
		call _memcpy
		jmp label_sections_start

	label_custom_header:	
		mov rcx, rdi
		xor rdx, rdx
		mov edx, IMAGE_NT_HEADERS64.OptionalHeader.AddressOfEntryPoint[r12]
		lea rdx, [rbx + rdx]
		call create_free_lib_header

	label_sections_start:
		xor r13, r13
		mov r13w, IMAGE_NT_HEADERS64.FileHeader.NumberOfSections[r12]
		lea rbx, [r12 + SIZEOF IMAGE_NT_HEADERS64]
		xor r12, r12		

	label_next_section:
		cmp r12, r13
		jge label_done

		mov rax, SIZEOF IMAGE_SECTION_HEADER
		mul r12
		lea rax, [rbx + rax]
		xor rcx, rcx
		mov ecx, IMAGE_SECTION_HEADER.VirtualAddress[rax]
		lea rcx, [rdi + rcx]
		xor rdx, rdx
		mov edx, IMAGE_SECTION_HEADER.PointerToRawData[rax]
		lea rdx, [rsi + rdx]
		xor r8, r8
		mov r8d, IMAGE_SECTION_HEADER.SizeOfRawData[rax]
		call _memcpy

		; Next section
		inc r12
		jmp label_next_section

	label_done:
		xor rax, rax				; SPEL64_R_OK		
		
	label_return:
		mov r13, [rbp - 28h]
		mov r12, [rbp - 20h]
		mov rbx, [rbp - 18h]
		mov rsi, [rbp - 10h]
		mov rdi, [rbp - 08h]
		lea rsp, [rbp]
		pop rbp
		ret

	map_image ENDP

	; @param	IMAGE_NT_HEADERS64*		NT Headers
	; @param	char*					Dest buffer
	; @param	char*					Remote buffer
	; @return	eSpelResponse
	init_base_relocations PROC

		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 20h]
		mov [rbp - 08h], rbx
		mov [rbp - 10h], r12
		mov [rbp - 18h], r13

		lea rax, IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[rcx]
		lea r11, [rax + IMAGE_DIRECTORY_ENTRY_BASERELOC * SIZEOF IMAGE_DATA_DIRECTORY]	; pDataDir	IMAGE_DATA_DIRECTORY*

		xor r9, r9
		mov r9d, IMAGE_DATA_DIRECTORY.VirtualAddress[r11]
		lea rbx, [rdx + r9]																; pReloc IMAGE_BASE_RELOCATION*

		mov rax, IMAGE_NT_HEADERS64.OptionalHeader.ImageBase[rcx]
		mov r10, r8
		sub r10, rax																	; Delta from preferred image base

		xor rax, rax
		mov eax, IMAGE_DATA_DIRECTORY._Size[r11]
		lea r12, [rbx + rax]															; pEnd

	label_next_base:
		cmp rbx, r12
		jge label_return

		xor rax, rax
		mov eax, IMAGE_BASE_RELOCATION.SizeOfBlock[rbx]
		sub rax, SIZEOF IMAGE_BASE_RELOCATION
		shr rax, 1																		; Number of relocations
		lea r9, [rbx + SIZEOF IMAGE_BASE_RELOCATION]									; pRelocEntry
		lea r11, [r9 + 2 * rax]															; pEnd	

	label_next_reloc:
		cmp r9, r11
		jge label_base_end

		xor rcx, rcx	
		mov ax, word ptr [r9]
		and ax, 0FFFh																	; pRelocEntry[i].offset
		mov ecx, IMAGE_BASE_RELOCATION.VirtualAddress[rbx]
		lea rcx, [rcx + rdx]
		lea rcx, [rcx + rax]															; pTarget
		
		xor r8, r8
		mov r8w, word ptr [r9]
		shr r8w, 12																		; pRelocEntry[i].type

		cmp r8b, IMAGE_REL_BASED_DIR64
		jne label_rel_highlow
		add qword ptr [rcx], r10
		jmp label_reloc_end

	label_rel_highlow:
		cmp r8b, IMAGE_REL_BASED_HIGHLOW
		jne label_rel_high
		add dword ptr [rcx], r10d
		jmp label_reloc_end

	label_rel_high:
		cmp r8b, IMAGE_REL_BASED_HIGH
		jne label_rel_low
		mov eax, r10d
		shr eax, 10h
		add word ptr [rcx], ax
		jmp label_reloc_end

	label_rel_low:
		cmp r8b, IMAGE_REL_BASED_LOW
		jne label_reloc_end
		mov word ptr [rcx], r10w

	label_reloc_end:
		lea r9, [r9 + 2]
		jmp label_next_reloc

	label_base_end:
		xor rax, rax
		mov eax, IMAGE_BASE_RELOCATION.SizeOfBlock[rbx]
		lea rbx, [rbx + rax]
		jmp label_next_base

	label_return:
		xor rax, rax				; SPEL64_R_OK
		mov r13, [rbp - 18h]
		mov r12, [rbp - 10h]
		mov rbx, [rbp - 08h]
		lea rsp, [rbp]
		pop rbp
		ret

	init_base_relocations ENDP

END
