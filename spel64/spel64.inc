EXTERN _memcpy:				PROC
EXTERN _zeromem:			PROC
EXTERN _memset:				PROC

EXTERN load_library_ex:		PROC
EXTERN free_library_ex:		PROC
EXTERN hijack_first_thread:	PROC

EXTERN GetCurrentProcess:	PROC
EXTERN CreateRemoteThread:	PROC
EXTERN WaitForSingleObject:	PROC

; spel64::eThreadFlags
THREADFLAG_NONE			equ 0h
THREADFLAG_SYNC			equ 1h

FREE_LIB_SIGNATURE		equ 0D15EA5E1FEC7EDh

; Response codes
SPEL64_R_OK											equ 00
SPEL64_R_FAILED_TO_READ_FILE						equ 01
SPEL64_R_FAILED_TO_ALLOCATE_LOCAL_MEMORY			equ 02
SPEL64_R_FAILED_TO_ALLOCATE_REMOTE_MEMORY			equ 03
SPEL64_R_INVALID_PE_FORMAT							equ 04
SPEL64_R_FAILED_TO_CREATE_THREAD					equ 05
SPEL64_R_FAILED_TO_WRITE_REMOTE_MEMORY				equ 06
SPEL64_R_FAILED_TO_FREE_REMOTE_MEMORY				equ 07
SPEL64_R_FAILED_TO_READ_REMOTE_MEMORY				equ 08
SPEL64_R_FAILED_TO_CREATE_SNAPSHOT					equ 09
SPEL64_R_FAILED_TO_FIND_THREAD						equ 10
SPEL64_R_FAILED_TO_OPEN_THREAD						equ 11
SPEL64_R_FAILED_TO_SUSPEND_THREAD					equ 12
SPEL64_R_FAILED_TO_GET_THREAD_CONTEXT				equ 13
SPEL64_R_FAILED_TO_SET_THREAD_CONTEXT				equ 14

; Flags
SPEL64FLAG_NONE					equ 0
SPEL64FLAG_NO_PE_HEADER			equ 1
SPEL64FLAG_HIJACK_THREAD		equ 2
SPEL64FLAG_NO_LDR				equ 4


; Windows defs
DLL_PROCESS_DETACH		equ	0h
DLL_PROCESS_ATTACH		equ 1h

INFINITE				equ 0FFFFFFFFh
IMAGE_ORDINAL_FLAG64	equ 8000000000000000h
IMAGE_SIZEOF_SHORT_NAME	equ 08h

IMAGE_DOS_SIGNATURE		equ 5A4Dh
IMAGE_OS2_SIGNATURE		equ 454Eh
IMAGE_OS2_SIGNATURE_LE	equ 454Ch
IMAGE_VXD_SIGNATURE		equ 454Ch
IMAGE_NT_SIGNATURE		equ 4550h 

IMAGE_REL_BASED_HIGH	equ 1
IMAGE_REL_BASED_LOW		equ 2
IMAGE_REL_BASED_HIGHLOW	equ 3
IMAGE_REL_BASED_DIR64	equ 10

; Optional Headers Data Directories
IMAGE_NUMBEROF_DIRECTORY_ENTRIES		equ	10h
IMAGE_DIRECTORY_ENTRY_EXPORT			equ	00h	; Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT			equ	01h	; Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE			equ	02h	; Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION			equ	03h	; Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY			equ	04h	; Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC			equ	05h	; Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG				equ	06h	; Debug Directory
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE		equ	07h	; Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR			equ	08h	; RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS				equ	09h	; TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG		equ	0Ah	; Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT		equ	0Bh	; Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT				equ	0Ch	; Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT		equ	0Dh	; Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	equ	0Eh	; COM Runtime descriptor


offsetof MACRO s,m
    EXITM <s.&m>
ENDM

; Payload context structs
PEIC STRUCT 8h		
	pe_module_address				qword 0h
	pe_entry_point_address			qword 0h
	pe_import_descriptor_table		qword 0h
	load_library_address			qword 0h
	get_proc_addr_address			qword 0h
	add_function_table_address		qword 0h
	lp_reserved						qword 0h
PEIC ENDS

THC STRUCT 8h
	entry_point						qword 0h
	return_address					qword 0h
THC ENDS

PEFC STRUCT 8h
	pe_module_address				qword 0h
	pe_entry_point_address			qword 0h
	delete_function_table_address	qword 0h
PEFC ENDS

FREE_LIB_HEADER STRUCT 8h
	ullSignature					qword	FREE_LIB_SIGNATURE
	pEntryPoint						qword	0h
FREE_LIB_HEADER ENDS

; PE32+ structs
IMAGE_DOS_HEADER STRUCT
	e_magic							word		?	; Magic number
	e_cblp							word		?	; Bytes on last page of file
	e_cp							word		?	; Pages in file
	e_crlc							word		?	; Relocations
	e_cparhdr						word		?	; Size of header in paragraphs
	e_minalloc						word		?	; Minimum extra paragraphs needed
	e_maxalloc						word		?	; Maximum extra paragraphs needed
	e_ss							word		?	; Initial (relative) SS value
	e_sp							word		?	; Initial SP value
	e_csum							word		?	; Checksum
	e_ip							word		?	; Initial IP value
	e_cs							word		?	; Initial (relative) CS value
	e_lfarlc						word		?	; File address of relocation table
	e_ovno							word		?	; Overlay number
	e_res							word 4 DUP	(?)	; Reserved words
	e_oemid							word		?	; OEM identifier (for e_oeminfo)
	e_oeminfo						word		?	; OEM information; e_oemid specific
	e_res2							word 10 DUP	(?)	; Reserved words
	e_lfanew						dword		?	; File address of new exe header
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
	Machine							word	?
	NumberOfSections				word	?
	TimeDateStamp					dword	?
	PointerToSymbolTable			dword	?
	NumberOfSymbols					dword	?
	SizeOfOptionalHeader			word	?
	Characteristics					word	?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress					dword	?
    _Size							dword	?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
	Magic							word	?
	MajorLinkerVersion				byte	?
	MinorLinkerVersion				byte	?
	SizeOfCode						dword	?
	SizeOfInitializedData			dword	?
	SizeOfUninitializedData			dword	?
	AddressOfEntryPoint				dword	?
	BaseOfCode						dword	?
	ImageBase						qword	?
	SectionAlignment				dword	?
	FileAlignment					dword	?
	MajorOperatingSystemVersion		word	?
	MinorOperatingSystemVersion		word	?
	MajorImageVersion				word	?
	MinorImageVersion				word	?
	MajorSubsystemVersion			word	?
	MinorSubsystemVersion			word	?
	Win32VersionValue				dword	?
	SizeOfImage						dword	?
	SizeOfHeaders					dword	?
	CheckSum						dword	?
	Subsystem						word	?
	DllCharacteristics				word	?
	SizeOfStackReserve				qword	?
	SizeOfStackCommit				qword	?
	SizeOfHeapReserve				qword	?
	SizeOfHeapCommit				qword	?
	LoaderFlags						dword	?
	NumberOfRvaAndSizes				dword	?
	DataDirectory					IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES DUP (<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_NT_HEADERS64 STRUCT
    Signature						dword					?	; IMAGE_NT_SIGNATURE
    FileHeader						IMAGE_FILE_HEADER		<>
    OptionalHeader					IMAGE_OPTIONAL_HEADER64	<>
IMAGE_NT_HEADERS64 ENDS

IMAGE_SECTION_HEADER STRUCT 4h
    _Name							byte	IMAGE_SIZEOF_SHORT_NAME DUP (?)
	UNION
		PhysicalAddress				dword	?
		VirtualSize					dword	?
	ENDS
	VirtualAddress					dword	?
	SizeOfRawData					dword	?
	PointerToRawData				dword	?
	PointerToRelocations			dword	?
	PointerToLinenumbers			dword	?
	NumberOfRelocations				word	?
	NumberOfLinenumbers				word	?
	Characteristics					dword	?
IMAGE_SECTION_HEADER ENDS

IMAGE_IMPORT_DESCRIPTOR STRUCT 4h
	UNION
		Characteristics				dword ?
		OriginalFirstThunk			dword ?
	ENDS
	TimeDateStamp					dword ?
	ForwarderChain					dword ?
	_Name							dword ?		; "Name" (and "Length") are reserved words
	FirstThunk						dword ?
IMAGE_IMPORT_DESCRIPTOR ENDS

IMAGE_THUNK_DATA64 STRUCT 8h
	UNION
		AddressOfData				qword ?
		Ordinal						qword ?
	ENDS
IMAGE_THUNK_DATA64 ENDS

IMAGE_IMPORT_BY_NAME STRUCT
	Hint							word ?
	_Name							byte ?
IMAGE_IMPORT_BY_NAME ENDS

IMAGE_BASE_RELOCATION STRUCT
    VirtualAddress					dword ?
    SizeOfBlock						dword ?
IMAGE_BASE_RELOCATION ENDS