#pragma once
#include "driver_includes.hpp"
#include "driver_shared.hpp"

namespace ioctl {

	inline bool inited = false;
	inline HANDLE device_handle = INVALID_HANDLE_VALUE;

	__int64 send_request(void* cmd);

	bool copy_virtual_memory(uint64_t src_pid, uint64_t dst_pid, void* src, void* dst, uint64_t size);
	uint64_t get_cr3(uint64_t pid);
	uint64_t get_pid_by_name(const char* name);
	uint64_t get_ldr_data_table_entry_count(uint64_t pid);
	bool get_data_table_entry_info(uint64_t pid, module_info_t* info_array);
	bool ping_driver(void);

	inline bool init_roseware_lib() {
		if (inited)
			return true;

		device_handle = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

		if (device_handle == INVALID_HANDLE_VALUE) {
			logging("Failed to open driver device");
			return false;
		}

		inited = true;

		if (!ping_driver()) {
			logging("Driver is not loaded");
			CloseHandle(device_handle);
			device_handle = INVALID_HANDLE_VALUE;
			inited = false;
			return false;
		}


		return true;
	}

	inline bool is_lib_inited(void) {
		return inited;
	}
};
