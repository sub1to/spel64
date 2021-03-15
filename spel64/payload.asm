INCLUDE spel64.inc

; seh_setup pe_init_context.pe_module_address, pe_init_context.add_function_table_address
; seh_setup pe_free_context.pe_module_address, pe_free_context.delete_function_table_address
seh_setup MACRO module, winapi_fn
	push rbp
	mov rbp, rsp 
	lea rsp, [rsp-20h]

	mov r8, module

	; Get the directory
	mov ecx, DWORD PTR IMAGE_DOS_HEADER.e_lfanew[r8]
	add rcx, module
	lea rcx, IMAGE_NT_HEADERS64.OptionalHeader.DataDirectory[rcx]
	add rcx, 18h													; IMAGE_DIRECTORY_ENTRY_EXCEPTION * sizeof(IMAGE_DATA_DIRECTORY)
	mov eax, DWORD PTR IMAGE_DATA_DIRECTORY._Size[rcx]
	test eax, eax
	jz macro_return

	; Divide the directory size by the entry size
	xor rdx, rdx
	mov r9, 0Ch														; sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)	= C
	div r9
	mov edx, eax

	; Get pointer to the table
	mov ecx, DWORD PTR IMAGE_DATA_DIRECTORY.VirtualAddress[rcx]
	add rcx, module

	mov rax, winapi_fn
	call rax

macro_return:
	mov rsp, rbp
	pop rbp
	ret
ENDM

.DATA

.CODE

	PUBLIC pe_init_context
	pe_init_context PEIC <?>

	PUBLIC pe_init
	pe_init PROC

		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 20h]

		call pe_imports
		call pe_add_seh

		; Call entry point
		mov rax, pe_init_context.pe_entry_point_address
		mov rcx, pe_init_context.pe_module_address
		mov rdx, DLL_PROCESS_ATTACH
		mov r8, pe_init_context.lp_reserved
		call rax

		lea rsp, [rbp]
		pop rbp
		ret

	pe_init ENDP

	
	pe_imports PROC
		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 50h]			; 28h saved non-volatile registers, 8h stack alignment, 20h shadow space

		; Push non-volatile registers to the stack
		mov [rbp - 08h], rbx
		mov [rbp - 10h], r12
		mov [rbp - 18h], r13
		mov [rbp - 20h], r14
		mov [rbp - 28h], r15

		mov rbx, pe_init_context.pe_import_descriptor_table
		mov r15, pe_init_context.pe_module_address

	pe_imports_next_descriptor:
		xor rax, rax
		mov eax, dword ptr IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk[rbx]
		and eax, eax
		jz pe_imports_return
	
		lea r12, [rax + r15]											; pOriginalFirstThunk		
		mov eax, dword ptr IMAGE_IMPORT_DESCRIPTOR.FirstThunk[rbx]		; mov eax, [rbx + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)]
		lea r13, [rax + r15]											; pFirstThunk		
		mov eax, dword ptr IMAGE_IMPORT_DESCRIPTOR._Name[rbx]			; mov eax, [rbx + offsetof(IMAGE_IMPORT_DESCRIPTOR, _Name)]
		lea rcx, [r15 + rax]
		
		mov rax, pe_init_context.load_library_address
		call rax

		and rax, rax
		jz pe_imports_descriptor_end	; Failed to load library

		mov r14, rax					; hModule

	pe_imports_next_thunk:		
		mov rdx, [r12]					; AddressOfData / Ordinal
		and rdx, rdx
		jz pe_imports_descriptor_end	; End of thunk data

		mov rax, rdx
		;shr rax, 3Fh					; IMAGE_ORDINAL_FLAG64 = most significant bit
		;and rax, 1
		mov rcx, IMAGE_ORDINAL_FLAG64
		and rax, rcx
		jnz pe_imports_import_by_ordinal

		lea rdx, IMAGE_IMPORT_BY_NAME._Name[r15 + rdx]		; lea rdx, [r15 + rdx + 2]; hModule + AddressOfData = pImportByName
		jmp pe_imports_patch

	pe_imports_import_by_ordinal:
		and rdx, 0FFFFh

	pe_imports_patch:
		lea rcx, [r14]
		mov rax, pe_init_context.get_proc_addr_address
		call rax

		and rax, rax
		jz pe_imports_thunk_end			; GetProcAddress failed

		mov [r13], rax					; Patch the import

	pe_imports_thunk_end:
		lea r12, [r12 + SIZEOF IMAGE_THUNK_DATA64]
		lea r13, [r13 + SIZEOF IMAGE_THUNK_DATA64]
		jmp pe_imports_next_thunk

	pe_imports_descriptor_end:
		lea rbx, [rbx + SIZEOF IMAGE_IMPORT_DESCRIPTOR]
		jmp pe_imports_next_descriptor

	pe_imports_return:
		mov rbx, [rbp - 08h]
		mov r12, [rbp - 10h]
		mov r13, [rbp - 18h]
		mov r14, [rbp - 20h]
		mov r15, [rbp - 28h]
		lea rsp, [rbp]
		pop rbp
		ret

	pe_imports ENDP

	pe_add_seh PROC
		seh_setup pe_init_context.pe_module_address, pe_init_context.add_function_table_address
	pe_add_seh ENDP

	PUBLIC pe_init_end
	pe_init_end PROC
		int 3
	pe_init_end ENDP




	PUBLIC thread_hijacker_context
	thread_hijacker_context THC <?>

	PUBLIC thread_hijacker
	thread_hijacker PROC
		; Push volatile registers to the stack
		push rax
		push rcx
		push rdx
		push r8
		push r9
		push r10
		push r11
		lea rsp, [rsp - 60h]
		movdqu oword ptr [rsp + 00h], xmm0
		movdqu oword ptr [rsp + 10h], xmm1
		movdqu oword ptr [rsp + 20h], xmm2
		movdqu oword ptr [rsp + 30h], xmm3
		movdqu oword ptr [rsp + 40h], xmm4
		movdqu oword ptr [rsp + 50h], xmm5

		; Auto stack alignment
		lea rsp, [rsp - 28h]				; 8h alignemnt offset + 20h shadow space
		mov rax, rsp
		and rax, 8h
		sub rsp, rax
		mov [rsp + 20h], rax				; Save alignment offset

		; Call the entry point		
		mov rax, thread_hijacker_context.entry_point
		call rax
		
		; Auto stack alignment
		mov rax, [rsp + 20h]				; Read alignment offset
		add rsp, rax
		lea rsp, [rsp + 28h]

		; Restore the volatile registers
		movdqu xmm5, oword ptr [rsp + 50h]
		movdqu xmm4, oword ptr [rsp + 40h]
		movdqu xmm3, oword ptr [rsp + 30h]
		movdqu xmm2, oword ptr [rsp + 20h]
		movdqu xmm1, oword ptr [rsp + 10h]
		movdqu xmm0, oword ptr [rsp + 00h]
		lea rsp, [rsp + 60h]
		pop r11
		pop r10
		pop r9
		pop r8
		pop rdx	

		; Signal that we're done
		lea rax, thread_hijacker_context.entry_point
		xor rcx, rcx
		mov [rax], rcx
		pop rcx
		
		; Push return value on the stack and pop rax	
		mov rax, thread_hijacker_context.return_address
		xchg rax, [rsp]

		ret
	thread_hijacker ENDP

	PUBLIC thread_hijacker_end
	thread_hijacker_end PROC
		int 3
	thread_hijacker_end ENDP





	PUBLIC pe_free_context
	pe_free_context PEFC <?>

	PUBLIC pe_free
	pe_free PROC

		push rbp
		lea rbp, [rsp]
		lea rsp, [rsp - 20h]

		; Call entry point
		mov rax, pe_free_context.pe_entry_point_address
		mov rcx, pe_free_context.pe_module_address
		mov rdx, DLL_PROCESS_DETACH
		xor r8, r8
		call rax

		call pe_del_seh

		lea rsp, [rbp]
		pop rbp
		ret

	pe_free ENDP

	pe_del_seh PROC
		seh_setup pe_free_context.pe_module_address, pe_free_context.delete_function_table_address
	pe_del_seh ENDP

	PUBLIC pe_free_end
	pe_free_end PROC
		int 3
	pe_free_end ENDP


END