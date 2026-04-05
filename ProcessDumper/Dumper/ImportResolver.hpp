#pragma once
#include "../Api/proc/process.hpp"
#include <vector>
#include <string>
#include <map>
#include <unordered_map>

struct ResolvedImport {
	std::string ModuleName;
	std::string FunctionName;
	uint64_t Address;
};

class ImportResolver {
public:
	bool Resolve(std::vector<uint8_t>& Buffer, uint64_t ImageBase);

private:
	void CollectExports();
	void ScanRdata(uint8_t* Buffer, uint64_t BufferSize, uint64_t ImageBase);
	bool BuildImportSection(std::vector<uint8_t>& Buffer, uint64_t ImageBase);
	void PatchCodeReferences(std::vector<uint8_t>& Buffer, uint64_t ImageBase);

	uint64_t RvaToOffset(uint8_t* Buffer, uint64_t Rva);

	std::unordered_map<uint64_t, ResolvedImport> ExportMap;
	std::map<std::string, std::vector<ResolvedImport>> GroupedImports;
	std::unordered_map<uint64_t, uint32_t> ValueToNewIatRva;
};
