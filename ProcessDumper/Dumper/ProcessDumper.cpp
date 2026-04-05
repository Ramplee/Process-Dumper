#include "ProcessDumper.hpp"
#include <Psapi.h>
#include <fstream>

ProcessDumper::ProcessDumper()
	: ImageBase(0), ImageSize(0), Attached(false), DecryptionThreshold(1.0f) {}

ProcessDumper::~ProcessDumper() {
	Monitor.Stop();
}

bool ProcessDumper::Attach(const std::string& ProcessName) {
	this->ProcessName = ProcessName;

	if (!process::attach_to_proc(ProcessName)) {
		log("Failed to attach to %s", ProcessName.c_str());
		return false;
	}

	log("Attached to %s (PID: %llu)", ProcessName.c_str(), process::target_pid);

	std::string ModuleName = ProcessName;
	size_t DotPos = ModuleName.find_last_of('.');
	if (DotPos == std::string::npos)
		ModuleName += ".exe";

	ImageBase = process::get_module_base(ModuleName);
	if (!ImageBase) {
		log("Failed to get image base for %s", ModuleName.c_str());
		return false;
	}

	ImageSize = process::get_module_size(ModuleName);
	if (!ImageSize) {
		log("Failed to get image size for %s", ModuleName.c_str());
		return false;
	}

	log("Image: 0x%llX | Size: 0x%llX (%llu KB)", ImageBase, ImageSize, ImageSize / 1024);

	DumpBuffer.resize(ImageSize, 0);

	if (!ReadInitialImage())
		log("Warning: Initial image read incomplete, monitor will fill in the rest");

	Attached = true;
	return true;
}

bool ProcessDumper::StartMonitoring() {
	if (!Attached) {
		log("Not attached");
		return false;
	}

	if (!Monitor.Init(ImageBase, ImageSize)) {
		log("Failed to init page monitor");
		return false;
	}

	Monitor.SetCallback([this](const DecryptedRegion& Region) {
		OnPageDecrypted(Region);
	});

	Monitor.Start();
	log("Monitor started - scanning pages via driver");
	return true;
}

bool ProcessDumper::DumpCurrent() {
	Monitor.Stop();
	log("Monitor stopped");
	return true;
}

bool ProcessDumper::Rebuild(const std::string& OutputPath) {
	std::lock_guard<std::mutex> Lock(DumpMutex);

	if (!Rebuilder.LoadFromBuffer(DumpBuffer.data(), DumpBuffer.size(), ImageBase)) {
		log("Failed to parse dump buffer");
		return false;
	}

	Rebuilder.FixHeaders();
	Rebuilder.FixSectionHeaders();
	Rebuilder.FixImportDirectory();

	ExceptionFixer::Fix(DumpBuffer.data(), DumpBuffer.size());

	Resolver.Resolve(DumpBuffer, ImageBase);

	if (!Rebuilder.LoadFromBuffer(DumpBuffer.data(), DumpBuffer.size(), ImageBase)) {
		log("Failed to reparse after import resolution");
		return false;
	}

	Rebuilder.NullRelocations();

	return Rebuilder.SaveToDisk(OutputPath);
}

void ProcessDumper::SetDecryptionThreshold(float Threshold) {
	DecryptionThreshold = Threshold;
	if (DecryptionThreshold < 0.0f) DecryptionThreshold = 0.0f;
	if (DecryptionThreshold > 1.0f) DecryptionThreshold = 1.0f;
}

uint64_t ProcessDumper::GetImageBase() const { return ImageBase; }
uint64_t ProcessDumper::GetImageSize() const { return ImageSize; }
uint64_t ProcessDumper::GetDecryptedCount() const { return Monitor.GetDecryptedCount(); }
uint64_t ProcessDumper::GetTotalPages() const { return Monitor.GetTotalPages(); }
bool ProcessDumper::IsMonitoring() const { return Monitor.IsRunning(); }

float ProcessDumper::GetDecryptionProgress() const {
	uint64_t Total = Monitor.GetTotalPages();
	if (Total == 0) return 0.0f;
	return (float)Monitor.GetDecryptedCount() / (float)Total;
}

void ProcessDumper::OnPageDecrypted(const DecryptedRegion& Region) {
	std::lock_guard<std::mutex> Lock(DumpMutex);

	uint64_t Offset = Region.BaseAddress - ImageBase;
	if (Offset + Region.Size > DumpBuffer.size())
		return;

	memcpy(DumpBuffer.data() + Offset, Region.Data.data(), Region.Size);
}

bool ProcessDumper::ReadInitialImage() {
	constexpr uint64_t ChunkSize = 0x1000;
	uint64_t PagesRead = 0;
	uint64_t TotalPages = ImageSize / ChunkSize;

	std::string DiskPath = GetTargetFilePath();
	std::ifstream DiskFile;
	std::vector<uint8_t> DiskBuffer;

	if (!DiskPath.empty()) {
		DiskFile.open(DiskPath, std::ios::binary);
		if (DiskFile.is_open()) {
			DiskFile.seekg(0, std::ios::end);
			auto FileSize = DiskFile.tellg();
			DiskFile.seekg(0, std::ios::beg);
			DiskBuffer.resize(FileSize);
			DiskFile.read(reinterpret_cast<char*>(DiskBuffer.data()), FileSize);
			DiskFile.close();
			log("Loaded on-disk PE fallback: %s (%llu bytes)", DiskPath.c_str(), DiskBuffer.size());
		}
	}

	for (uint64_t Offset = 0; Offset < ImageSize; Offset += ChunkSize) {
		uint64_t ReadSize = min(ChunkSize, ImageSize - Offset);

		bool Ok = process::read_array(
			DumpBuffer.data() + Offset,
			(void*)(ImageBase + Offset),
			ReadSize);

		if (Ok) {
			PagesRead++;
			continue;
		}

		if (!DiskBuffer.empty() && Offset + ReadSize <= DiskBuffer.size()) {
			memcpy(DumpBuffer.data() + Offset, DiskBuffer.data() + Offset, ReadSize);
			PagesRead++;
		}
	}

	log("Initial read: %llu / %llu pages", PagesRead, TotalPages);
	return PagesRead > 0;
}

bool ProcessDumper::ReadFromDisk(uint64_t Offset, uint64_t Size, uint8_t* Dest) {
	std::string Path = GetTargetFilePath();
	if (Path.empty())
		return false;

	std::ifstream File(Path, std::ios::binary);
	if (!File.is_open())
		return false;

	File.seekg(Offset);
	File.read(reinterpret_cast<char*>(Dest), Size);
	return File.good();
}

std::string ProcessDumper::GetTargetFilePath() {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)process::target_pid);
	if (!hProc)
		return "";

	char Path[MAX_PATH] = {};
	DWORD PathSize = MAX_PATH;
	QueryFullProcessImageNameA(hProc, 0, Path, &PathSize);
	CloseHandle(hProc);

	return std::string(Path);
}
