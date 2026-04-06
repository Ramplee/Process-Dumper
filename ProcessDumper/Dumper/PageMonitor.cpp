#include "PageMonitor.hpp"

PageMonitor::PageMonitor()
	: ImageBase(0), ImageSize(0), Running(false), DecryptedCount(0), TotalPages(0), OnDecrypted(nullptr) {}

PageMonitor::~PageMonitor() {
	Stop();
}

bool PageMonitor::Init(uint64_t ImageBase, uint64_t ImageSize) {
	this->ImageBase = ImageBase;
	this->ImageSize = ImageSize;

	constexpr uint64_t PageSize = 0x1000;
	TotalPages = (ImageSize + PageSize - 1) / PageSize;

	Pages.resize(TotalPages);
	for (uint64_t i = 0; i < TotalPages; i++) {
		Pages[i].Address = ImageBase + (i * PageSize);
		Pages[i].Size = PageSize;
		Pages[i].State = PageState::Unknown;
		Pages[i].ContentHash = 0;
		Pages[i].LastProtect = PAGE_NOACCESS;
	}

	ReadBuffer.resize(PageSize);

	logging("Initialized monitor: 0x%llX | %llu pages", ImageBase, TotalPages);
	return true;
}

void PageMonitor::SetCallback(DecryptionCallback Callback) {
	OnDecrypted = Callback;
}

void PageMonitor::Start() {
	if (Running)
		return;
	Running = true;
	Worker = std::thread(&PageMonitor::MonitorThread, this);
}

void PageMonitor::Stop() {
	Running = false;
	if (Worker.joinable())
		Worker.join();
}

bool PageMonitor::IsRunning() const {
	return Running;
}

uint64_t PageMonitor::GetDecryptedCount() const {
	return DecryptedCount;
}

uint64_t PageMonitor::GetTotalPages() const {
	return TotalPages;
}

void PageMonitor::MonitorThread() {
	constexpr uint64_t PageSize = 0x1000;
	HANDLE TargetHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)process::target_pid);
	if (!TargetHandle) {
		logging("Monitor could not open target handle for protection checks");
		Running = false;
		return;
	}
	std::vector<uint8_t> LocalBuffer(PageSize);

	while (Running) {
		for (uint64_t i = 0; i < TotalPages && Running; i++) {
			TrackedPage& Page = Pages[i];

			if (Page.State == PageState::Decrypted)
				continue;

			MEMORY_BASIC_INFORMATION Mbi{};
			if (VirtualQueryEx(TargetHandle, (LPCVOID)Page.Address, &Mbi, sizeof(Mbi)) == 0)
				continue;

			DWORD CurrentProtect = Mbi.Protect;
			bool WasNoAccess = IsNoAccessProtect(Page.LastProtect);
			bool IsReadableNow = IsReadableProtect(CurrentProtect);
			Page.LastProtect = CurrentProtect;

			// We only capture when a page transitions away from NO_ACCESS
			if (!WasNoAccess || !IsReadableNow)
				continue;

			memset(LocalBuffer.data(), 0, PageSize);

			bool ReadOk = process::read_array(LocalBuffer.data(), (void*)Page.Address, PageSize);
			if (!ReadOk)
				continue;

			bool Empty = IsPageEmpty(LocalBuffer.data(), PageSize);

			if (Empty) {
				if (Page.State == PageState::Unknown)
					Page.State = PageState::Empty;
				continue;
			}

			uint64_t Hash = HashPage(LocalBuffer.data(), PageSize);

			if (Page.State == PageState::Empty || Page.State == PageState::Unknown) {
				Page.State = PageState::Decrypted;
				Page.ContentHash = Hash;

				DecryptedRegion Region;
				Region.BaseAddress = Page.Address;
				Region.Size = PageSize;
				Region.Data.assign(LocalBuffer.begin(), LocalBuffer.end());

				if (OnDecrypted) {
					OnDecrypted(Region);
				}

				DecryptedCount++;
			}
		}
		Sleep(1);
	}

	CloseHandle(TargetHandle);
}

uint64_t PageMonitor::HashPage(const uint8_t* Data, uint64_t Size) {
	uint64_t Hash = 0x517CC1B727220A95;
	for (uint64_t i = 0; i < Size; i++) {
		Hash ^= Data[i];
		Hash *= 0x5BD1E995;
		Hash ^= Hash >> 15;
	}
	return Hash;
}

bool PageMonitor::IsPageEmpty(const uint8_t* Data, uint64_t Size) {
	const uint64_t* QuadData = reinterpret_cast<const uint64_t*>(Data);
	uint64_t QuadCount = Size / sizeof(uint64_t);

	for (uint64_t i = 0; i < QuadCount; i++) {
		if (QuadData[i] != 0)
			return false;
	}
	return true;
}

bool PageMonitor::IsNoAccessProtect(DWORD Protect) const {
	DWORD BaseProtect = Protect & 0xFF;
	return BaseProtect == PAGE_NOACCESS;
}

bool PageMonitor::IsReadableProtect(DWORD Protect) const {
	DWORD BaseProtect = Protect & 0xFF;
	switch (BaseProtect) {
	case PAGE_EXECUTE_READ:
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
	case PAGE_READONLY:
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
		return true;
	default:
		return false;
	}
}
