.DATA

.CODE

	PUBLIC _memcpy
	PUBLIC _zeromem
	PUBLIC _memset


	_memcpy PROC
		push rsi
		push rdi
		push r8
		
		cld				; clear directional flag
		mov rsi, rdx	; source
		mov rdi, rcx	; dest

		; Move 8 bytes at a time
		mov rcx, r8
		shr rcx, 3		; Divide length by 8
		rep movsq

		; Move remainder 1 byte at a time
		pop rcx
		and rcx, 7		; Get remainder of the division
		rep movsb

		pop rdi
		pop rsi
		ret
	_memcpy ENDP

	
	_zeromem PROC
		push rdi
		push rdx
		
		cld				; clear directional flag
		mov rdi, rcx	; dest
		xor rax, rax	; val

		; Move 8 bytes at a time
		mov rcx, rdx
		shr rcx, 3		; Divide length by 8
		rep stosq

		; Move remainder 1 byte at a time
		pop rcx
		and rcx, 7		; Get remainder of the division
		rep stosb

		pop rdi
		ret
	_zeromem ENDP

	
	_memset PROC
		push rdi
		
		cld				; clear directional flag
		xor rax, rax
		mov al, dl		; val
		mov rdi, rcx	; dest
		mov rcx, r8		; len
		rep stosb

		pop rdi
		ret
	_memset ENDP


END