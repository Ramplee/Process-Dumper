#include "PeRebuilder.hpp"
#include "../Api/driver/driver_includes.hpp"
#include <fstream>

PeRebuilder::PeRebuilder()
	: RawBuffer(nullptr), BufferSize(0), OriginalImageBase(0),
	  DosHeader(nullptr), NtHeaders(nullptr), SectionHeaders(nullptr) {}

bool PeRebuilder::LoadFromBuffer(uint8_t* Buffer, uint64_t Size, uint64_t ImageBase) {
	RawBuffer = Buffer;
	BufferSize = Size;
	OriginalImageBase = ImageBase;

	DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(RawBuffer);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		logging("Invalid DOS signature: 0x%X", DosHeader->e_magic);
		return false;
	}

	NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(RawBuffer + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		logging("Invalid NT signature: 0x%X", NtHeaders->Signature);
		return false;
	}

	if (NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		logging("Not a 64bit PE");
		return false;
	}

	SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);

	logging("PE loaded: %d sections, ImageBase: 0x%llX, ImageSize: 0x%X",
		NtHeaders->FileHeader.NumberOfSections,
		NtHeaders->OptionalHeader.ImageBase,
		NtHeaders->OptionalHeader.SizeOfImage);

	return true;
}

bool PeRebuilder::FixHeaders() {
	NtHeaders->OptionalHeader.ImageBase = OriginalImageBase;

	NtHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	NtHeaders->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	uint32_t FileAlignment = NtHeaders->OptionalHeader.FileAlignment;
	uint32_t SectionAlignment = NtHeaders->OptionalHeader.SectionAlignment;

	if (FileAlignment == 0)
		NtHeaders->OptionalHeader.FileAlignment = 0x200;
	if (SectionAlignment == 0)
		NtHeaders->OptionalHeader.SectionAlignment = 0x1000;

	logging("Headers fixed: ASLR disabled, relocations stripped");
	return true;
}

bool PeRebuilder::FixSectionHeaders() {
	uint32_t FileAlignment = NtHeaders->OptionalHeader.FileAlignment;
	uint16_t SectionCount = NtHeaders->FileHeader.NumberOfSections;

	uint32_t FirstSectionOffset = AlignValue(
		DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (SectionCount * sizeof(IMAGE_SECTION_HEADER)),
		NtHeaders->OptionalHeader.FileAlignment);

	NtHeaders->OptionalHeader.SizeOfHeaders = FirstSectionOffset;

	for (uint16_t i = 0; i < SectionCount; i++) {
		IMAGE_SECTION_HEADER& Section = SectionHeaders[i];

		Section.PointerToRawData = Section.VirtualAddress;
		Section.SizeOfRawData = AlignValue(Section.Misc.VirtualSize, FileAlignment);

		if (Section.SizeOfRawData == 0)
			Section.SizeOfRawData = AlignValue(Section.Misc.VirtualSize, FileAlignment);

		if (Section.Misc.VirtualSize == 0)
			Section.Misc.VirtualSize = Section.SizeOfRawData;

		logging("Section %-8.8s | VA: 0x%08X | VSize: 0x%08X | RawPtr: 0x%08X | RawSize: 0x%08X",
			Section.Name, Section.VirtualAddress, Section.Misc.VirtualSize,
			Section.PointerToRawData, Section.SizeOfRawData);
	}

	return true;
}

bool PeRebuilder::FixImportDirectory() {
	auto& ImportDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (ImportDir.VirtualAddress == 0 || ImportDir.Size == 0)
		return true;

	uint64_t ImportOffset = RvaToOffset(ImportDir.VirtualAddress);
	if (ImportOffset == 0 || ImportOffset >= BufferSize) {
		logging("Import directory RVA points outside buffer");
		return false;
	}

	auto* ImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(RawBuffer + ImportOffset);

	uint32_t ImportCount = 0;
	while (ImportDesc->Name != 0) {
		uint64_t NameOffset = RvaToOffset(ImportDesc->Name);
		if (NameOffset && NameOffset < BufferSize) {
			const char* DllName = reinterpret_cast<const char*>(RawBuffer + NameOffset);
			logging("Import: %s", DllName);
		}
		ImportDesc++;
		ImportCount++;
	}

	logging("Fixed %d import descriptors", ImportCount);
	return true;
}

bool PeRebuilder::NullRelocations() {
	auto& RelocDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	RelocDir.VirtualAddress = 0;
	RelocDir.Size = 0;

	logging("Relocation directory nulled");
	return true;
}

bool PeRebuilder::SaveToDisk(const std::string& OutputPath) {
	std::ofstream File(OutputPath, std::ios::binary);
	if (!File.is_open()) {
		logging("Failed to create output file: %s", OutputPath.c_str());
		return false;
	}

	File.write(reinterpret_cast<const char*>(RawBuffer), BufferSize);
	File.close();

	logging("Dump saved: %s (%llu bytes)", OutputPath.c_str(), BufferSize);
	return true;
}

IMAGE_NT_HEADERS64* PeRebuilder::GetNtHeaders() const {
	return NtHeaders;
}

uint32_t PeRebuilder::GetSectionCount() const {
	if (!NtHeaders)
		return 0;
	return NtHeaders->FileHeader.NumberOfSections;
}

uint64_t PeRebuilder::RvaToOffset(uint64_t Rva) {
	uint16_t SectionCount = NtHeaders->FileHeader.NumberOfSections;

	for (uint16_t i = 0; i < SectionCount; i++) {
		IMAGE_SECTION_HEADER& Section = SectionHeaders[i];
		uint64_t SectionStart = Section.VirtualAddress;
		uint64_t SectionEnd = SectionStart + Section.Misc.VirtualSize;

		if (Rva >= SectionStart && Rva < SectionEnd) {
			return Rva - SectionStart + Section.PointerToRawData;
		}
	}

	return Rva;
}

IMAGE_SECTION_HEADER* PeRebuilder::FindSectionByRva(uint64_t Rva) {
	uint16_t SectionCount = NtHeaders->FileHeader.NumberOfSections;

	for (uint16_t i = 0; i < SectionCount; i++) {
		uint64_t Start = SectionHeaders[i].VirtualAddress;
		uint64_t End = Start + SectionHeaders[i].Misc.VirtualSize;

		if (Rva >= Start && Rva < End)
			return &SectionHeaders[i];
	}

	return nullptr;
}

uint32_t PeRebuilder::AlignValue(uint32_t Value, uint32_t Alignment) {
	if (Alignment == 0)
		return Value;
	return (Value + Alignment - 1) & ~(Alignment - 1);
}
