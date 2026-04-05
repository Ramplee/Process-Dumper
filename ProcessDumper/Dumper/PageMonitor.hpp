#pragma once
#include "../Api/proc/process.hpp"
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>

enum class PageState : uint8_t {
	Unknown,
	Empty,
	Decrypted
};

struct TrackedPage {
	uint64_t Address;
	uint64_t Size;
	PageState State;
	uint64_t ContentHash;
	DWORD LastProtect;
};

struct DecryptedRegion {
	uint64_t BaseAddress;
	uint64_t Size;
	std::vector<uint8_t> Data;
};

using DecryptionCallback = std::function<void(const DecryptedRegion&)>;

class PageMonitor {
public:
	PageMonitor();
	~PageMonitor();

	bool Init(uint64_t ImageBase, uint64_t ImageSize);
	void SetCallback(DecryptionCallback Callback);
	void Start();
	void Stop();
	bool IsRunning() const;
	uint64_t GetDecryptedCount() const;
	uint64_t GetTotalPages() const;

private:
	void MonitorThread();
	uint64_t HashPage(const uint8_t* Data, uint64_t Size);
	bool IsPageEmpty(const uint8_t* Data, uint64_t Size);
	bool IsNoAccessProtect(DWORD Protect) const;
	bool IsReadableProtect(DWORD Protect) const;

	uint64_t ImageBase;
	uint64_t ImageSize;

	std::vector<TrackedPage> Pages;
	std::mutex PageMutex;

	std::vector<uint8_t> ReadBuffer;

	std::thread Worker;
	std::atomic<bool> Running;
	std::atomic<uint64_t> DecryptedCount;
	uint64_t TotalPages;

	DecryptionCallback OnDecrypted;
};
