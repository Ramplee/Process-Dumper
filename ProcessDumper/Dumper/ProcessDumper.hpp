#pragma once
#include "PageMonitor.hpp"
#include "PeRebuilder.hpp"
#include "ImportResolver.hpp"
#include "ExceptionFixer.hpp"
#include <string>
#include <vector>
#include <mutex>

class ProcessDumper {
public:
	ProcessDumper();
	~ProcessDumper();

	bool Attach(const std::string& ProcessName);
	bool StartMonitoring();
	bool DumpCurrent();
	bool Rebuild(const std::string& OutputPath);

	void SetDecryptionThreshold(float Threshold);

	uint64_t GetImageBase() const;
	uint64_t GetImageSize() const;
	uint64_t GetDecryptedCount() const;
	uint64_t GetTotalPages() const;
	bool IsMonitoring() const;
	float GetDecryptionProgress() const;

private:
	void OnPageDecrypted(const DecryptedRegion& Region);
	bool ReadInitialImage();
	bool ReadFromDisk(uint64_t Offset, uint64_t Size, uint8_t* Dest);
	std::string GetTargetFilePath();

	std::string ProcessName;
	uint64_t ImageBase;
	uint64_t ImageSize;
	float DecryptionThreshold;

	std::vector<uint8_t> DumpBuffer;
	std::mutex DumpMutex;

	PageMonitor Monitor;
	PeRebuilder Rebuilder;
	ImportResolver Resolver;
	bool Attached;
};
