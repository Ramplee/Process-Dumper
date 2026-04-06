#include "ExceptionFixer.hpp"
#include "../Api/proc/process.hpp"
#include <Windows.h>


uint32_t ExceptionFixer::Fix(uint8_t* Buffer, uint64_t BufferSize) {
	auto* DosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(Buffer);
	if (DosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	auto* NtHdrs = reinterpret_cast<IMAGE_NT_HEADERS64*>(Buffer + DosHdr->e_lfanew);
	if (NtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	auto& ExceptDir = NtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (ExceptDir.VirtualAddress == 0 || ExceptDir.Size == 0)
		return 0;

	uint32_t Removed = 0;

	for (uint32_t Rva = ExceptDir.VirtualAddress;
		Rva < ExceptDir.VirtualAddress + ExceptDir.Size;
		Rva += sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
	{
		uint64_t Offset = RvaToOffset(Buffer, Rva);
		if (Offset == 0 || Offset + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) > BufferSize)
			continue;

		auto& Entry = *reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(Buffer + Offset);

		if (Entry.BeginAddress == 0 && Entry.EndAddress == 0)
			continue;

		uint64_t BeginOff = RvaToOffset(Buffer, Entry.BeginAddress);
		uint64_t EndOff = RvaToOffset(Buffer, Entry.EndAddress);
		uint64_t UnwindOff = RvaToOffset(Buffer, Entry.UnwindInfoAddress);

		bool Valid = BeginOff && BeginOff < BufferSize &&
			EndOff && EndOff < BufferSize &&
			UnwindOff && UnwindOff < BufferSize;

		if (Valid) {
			struct UnwindInfo {
				uint8_t Version : 3;
				uint8_t Flags : 5;
			};
			auto Info = *reinterpret_cast<UnwindInfo*>(Buffer + UnwindOff);
			if (Info.Version == 1)
				continue;
		}

		memset(Buffer + Offset, 0, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY));
		Removed++;
	}

	logging("Exception directory: removed %u invalid entries", Removed);
	return Removed;
}

uint64_t ExceptionFixer::RvaToOffset(uint8_t* Buffer, uint64_t Rva) {
	auto* DosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(Buffer);
	auto* NtHdrs = reinterpret_cast<IMAGE_NT_HEADERS64*>(Buffer + DosHdr->e_lfanew);
	auto* Sections = IMAGE_FIRST_SECTION(NtHdrs);

	for (uint16_t i = 0; i < NtHdrs->FileHeader.NumberOfSections; i++) {
		uint64_t Start = Sections[i].VirtualAddress;
		uint64_t End = Start + Sections[i].Misc.VirtualSize;
		if (Rva >= Start && Rva < End)
			return Rva - Start + Sections[i].PointerToRawData;
	}
	return Rva;
}
