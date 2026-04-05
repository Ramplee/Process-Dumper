#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <Windows.h>

class PeRebuilder {
public:
	PeRebuilder();

	bool LoadFromBuffer(uint8_t* Buffer, uint64_t Size, uint64_t ImageBase);
	bool FixHeaders();
	bool FixSectionHeaders();
	bool FixImportDirectory();
	bool NullRelocations();
	bool SaveToDisk(const std::string& OutputPath);

	IMAGE_NT_HEADERS64* GetNtHeaders() const;
	uint32_t GetSectionCount() const;

private:
	uint64_t RvaToOffset(uint64_t Rva);
	IMAGE_SECTION_HEADER* FindSectionByRva(uint64_t Rva);
	uint32_t AlignValue(uint32_t Value, uint32_t Alignment);

	uint8_t* RawBuffer;
	uint64_t BufferSize;
	uint64_t OriginalImageBase;

	IMAGE_DOS_HEADER* DosHeader;
	IMAGE_NT_HEADERS64* NtHeaders;
	IMAGE_SECTION_HEADER* SectionHeaders;
};
