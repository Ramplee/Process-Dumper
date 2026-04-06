#include <ntddk.h>
#include <intrin.h>
#include <cstdint>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define DEVICE_NAME L"\\Device\\PdIoctl"
#define SYMLINK_NAME L"\\DosDevices\\PdIoctl"
#define IOCTL_SEND_COMMAND CTL_CODE(0x800, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PEB_LDR_OFFSET 0x18

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

struct copy_virtual_memory_t {
	uint64_t src_pid;
	uint64_t dst_pid;
	void* src;
	void* dst;
	uint64_t size;
};

struct get_cr3_t {
	uint64_t pid;
	uint64_t cr3;
};

struct get_pid_by_name_t {
	char name[MAX_PATH];
	uint64_t pid;
};

struct get_ldr_data_table_entry_count_t {
	uint64_t pid;
	uint64_t count;
};

struct module_info_t {
	char name[MAX_PATH];
	uint64_t base;
	uint64_t size;
};

struct cmd_get_data_table_entry_info_t {
	uint64_t pid;
	module_info_t* info_array;
};

enum call_types_t : uint32_t {
	cmd_get_pid_by_name,
	cmd_get_cr3,
	cmd_get_ldr_data_table_entry_count,
	cmd_get_data_table_entry_info,
	cmd_copy_virtual_memory,
	cmd_ping_driver,
};

struct command_t {
	bool status;
	call_types_t call_type;
	void* sub_command_ptr;
};

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress;
			BOOLEAN SpecialApcInProgress;
		};
	};
	BOOLEAN KernelApcPending;
	union {
		BOOLEAN UserApcPendingAll;
		struct {
			BOOLEAN SpecialUserApcPending;
			BOOLEAN UserApcPending;
		};
	};
} KAPC_STATE, *PKAPC_STATE;

extern "C" {
	NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
		PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
	NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
	NTKERNELAPI VOID KeStackAttachProcess(PVOID Process, PKAPC_STATE ApcState);
	NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);
	NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
		ULONG SystemInformationLength, PULONG ReturnLength);

	void* HalPrivateDispatchTable;
}

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _PEB_LDR_DATA_FULL {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL, * PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL, * PLDR_DATA_TABLE_ENTRY_FULL;

PDEVICE_OBJECT g_device_object = nullptr;
UNICODE_STRING g_symlink_name = {};

// 0x400

void* o_halp_lbr_clear_stack = nullptr;

uint8_t halp_lbr_clear_stack_hook() {
	auto* process = IoGetCurrentProcess();
	if (process)
		*(uint64_t*)((uint8_t*)process + 0x28) = __readcr3();

	if (o_halp_lbr_clear_stack)
		return ((uint8_t(*)())o_halp_lbr_clear_stack)();

	return 0;
}

void init_hook() {
	UNICODE_STRING routine_string = RTL_CONSTANT_STRING(L"KeSetLastBranchRecordInUse");
	void* KeSetLastBranchRecordInUse = MmGetSystemRoutineAddress(&routine_string);
	if (!KeSetLastBranchRecordInUse)
		return;

	int32_t rel32 = *(int32_t*)((uint8_t*)KeSetLastBranchRecordInUse + 0x8);
	uint64_t rip = (uint64_t)KeSetLastBranchRecordInUse + 0x6;
	auto* ki_cpu_tracing_flags = (uint32_t*)(rip + rel32 + 0x7);

	if (!MmIsAddressValid(ki_cpu_tracing_flags))
		return;

	o_halp_lbr_clear_stack = *(void**)((uint8_t*)HalPrivateDispatchTable + 0x400);
	*(void**)((uint8_t*)HalPrivateDispatchTable + 0x400) = halp_lbr_clear_stack_hook;

	*ki_cpu_tracing_flags |= 2;
}

void unicode_to_ansi(UNICODE_STRING* src, char* dst, uint32_t max_len) {
	uint32_t len = src->Length / sizeof(WCHAR);
	if (len >= max_len)
		len = max_len - 1;
	for (uint32_t i = 0; i < len; i++)
		dst[i] = (char)src->Buffer[i];
	dst[len] = '\0';
}

NTSTATUS find_pid_by_name(const char* target_name, uint64_t* out_pid) {
	ULONG buffer_size = 0;
	ZwQuerySystemInformation(5, nullptr, 0, &buffer_size);
	if (!buffer_size)
		return STATUS_UNSUCCESSFUL;

	buffer_size += 0x10000;
	void* buffer = ExAllocatePoolWithTag(NonPagedPool, buffer_size, 'pdmp');
	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS status = ZwQuerySystemInformation(5, buffer, buffer_size, nullptr);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(buffer, 'pdmp');
		return status;
	}

	auto* entry = (SYSTEM_PROCESS_INFORMATION*)buffer;
	while (true) {
		if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
			char ansi_name[MAX_PATH] = {};
			unicode_to_ansi(&entry->ImageName, ansi_name, MAX_PATH);
			if (_stricmp(ansi_name, target_name) == 0) {
				*out_pid = (uint64_t)entry->UniqueProcessId;
				ExFreePoolWithTag(buffer, 'pdmp');
				return STATUS_SUCCESS;
			}
		}
		if (entry->NextEntryOffset == 0)
			break;
		entry = (SYSTEM_PROCESS_INFORMATION*)((uint8_t*)entry + entry->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, 'pdmp');
	return STATUS_NOT_FOUND;
}

NTSTATUS walk_process_modules(uint64_t pid, module_info_t* info_array, uint64_t* out_count, bool count_only) {
	PEPROCESS eprocess = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &eprocess);
	if (!NT_SUCCESS(status))
		return status;

	KAPC_STATE apc_state;
	KeStackAttachProcess((PRKPROCESS)eprocess, &apc_state);

	uint64_t module_count = 0;
	__try {
		PPEB peb = PsGetProcessPeb(eprocess);
		if (!peb) {
			KeUnstackDetachProcess(&apc_state);
			ObDereferenceObject(eprocess);
			return STATUS_UNSUCCESSFUL;
		}

		PPEB_LDR_DATA_FULL ldr = *(PPEB_LDR_DATA_FULL*)((uint8_t*)peb + PEB_LDR_OFFSET);
		if (!ldr || !ldr->Initialized) {
			KeUnstackDetachProcess(&apc_state);
			ObDereferenceObject(eprocess);
			return STATUS_UNSUCCESSFUL;
		}

		PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
		PLIST_ENTRY current = head->Flink;

		while (current != head) {
			auto* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

			if (!count_only && info_array) {
				module_info_t info = {};
				if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
					unicode_to_ansi(&entry->BaseDllName, info.name, MAX_PATH);
				info.base = (uint64_t)entry->DllBase;
				info.size = (uint64_t)entry->SizeOfImage;
				info_array[module_count] = info;
			}

			module_count++;
			current = current->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&apc_state);
		ObDereferenceObject(eprocess);
		return STATUS_ACCESS_VIOLATION;
	}

	KeUnstackDetachProcess(&apc_state);
	ObDereferenceObject(eprocess);

	if (out_count)
		*out_count = module_count;

	return STATUS_SUCCESS;
}

NTSTATUS handle_command(command_t* cmd) {
	if (!cmd->sub_command_ptr && cmd->call_type != cmd_ping_driver)
		return STATUS_INVALID_PARAMETER;

	switch (cmd->call_type) {
	case cmd_ping_driver: {
		cmd->status = true;
	} break;

	case cmd_get_pid_by_name: {
		get_pid_by_name_t sub_cmd = {};
		__try {
			RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		uint64_t pid = 0;
		NTSTATUS status = find_pid_by_name(sub_cmd.name, &pid);
		if (!NT_SUCCESS(status))
			return status;

		sub_cmd.pid = pid;
		__try {
			RtlCopyMemory(cmd->sub_command_ptr, &sub_cmd, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		cmd->status = true;
	} break;

	case cmd_get_cr3: {
		get_cr3_t sub_cmd = {};
		__try {
			RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		PEPROCESS eprocess = nullptr;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)sub_cmd.pid, &eprocess);
		if (!NT_SUCCESS(status))
			return status;

		sub_cmd.cr3 = *(uint64_t*)((uint8_t*)eprocess + 0x28);
		ObDereferenceObject(eprocess);

		if (!sub_cmd.cr3)
			return STATUS_UNSUCCESSFUL;

		__try {
			RtlCopyMemory(cmd->sub_command_ptr, &sub_cmd, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		cmd->status = true;
	} break;



	case cmd_get_ldr_data_table_entry_count: {
		get_ldr_data_table_entry_count_t sub_cmd = {};
		__try {
			RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		uint64_t count = 0;
		NTSTATUS status = walk_process_modules(sub_cmd.pid, nullptr, &count, true);
		if (!NT_SUCCESS(status))
			return status;

		sub_cmd.count = count;

		__try {
			RtlCopyMemory(cmd->sub_command_ptr, &sub_cmd, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		cmd->status = true;
	} break;

	case cmd_get_data_table_entry_info: {
		cmd_get_data_table_entry_info_t sub_cmd = {};
		__try {
			RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		if (!sub_cmd.info_array)
			return STATUS_INVALID_PARAMETER;

		uint64_t count = 0;
		NTSTATUS status = walk_process_modules(sub_cmd.pid, nullptr, &count, true);
		if (!NT_SUCCESS(status) || count == 0)
			return STATUS_UNSUCCESSFUL;

		auto* temp = (module_info_t*)ExAllocatePoolWithTag(NonPagedPool, sizeof(module_info_t) * count, 'pdmp');
		if (!temp)
			return STATUS_INSUFFICIENT_RESOURCES;

		RtlZeroMemory(temp, sizeof(module_info_t) * count);
		status = walk_process_modules(sub_cmd.pid, temp, &count, false);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(temp, 'pdmp');
			return status;
		}

		__try {
			RtlCopyMemory(sub_cmd.info_array, temp, sizeof(module_info_t) * count);
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			ExFreePoolWithTag(temp, 'pdmp');
			return STATUS_ACCESS_VIOLATION;
		}

		ExFreePoolWithTag(temp, 'pdmp');
		cmd->status = true;
	} break;

	case cmd_copy_virtual_memory: {
		copy_virtual_memory_t sub_cmd = {};
		__try {
			RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
		} __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

		if (!sub_cmd.src || !sub_cmd.dst || !sub_cmd.size || sub_cmd.size > 0x100000)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS src_process = nullptr;
		PEPROCESS dst_process = nullptr;

		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)sub_cmd.src_pid, &src_process);
		if (!NT_SUCCESS(status))
			return status;

		status = PsLookupProcessByProcessId((HANDLE)sub_cmd.dst_pid, &dst_process);
		if (!NT_SUCCESS(status)) {
			ObDereferenceObject(src_process);
			return status;
		}

		SIZE_T bytes_copied = 0;
		status = MmCopyVirtualMemory(src_process, sub_cmd.src, dst_process, sub_cmd.dst, sub_cmd.size, KernelMode, &bytes_copied);

		ObDereferenceObject(src_process);
		ObDereferenceObject(dst_process);

		if (!NT_SUCCESS(status))
			return status;

		cmd->status = true;
	} break;

	default:
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

NTSTATUS ioctl_dispatch(PDEVICE_OBJECT device, PIRP irp) {
	UNREFERENCED_PARAMETER(device);

	auto* stack = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG bytes_returned = 0;

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SEND_COMMAND) {
		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(command_t) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(command_t)) {

			auto* cmd = (command_t*)irp->AssociatedIrp.SystemBuffer;
			cmd->status = false;
			handle_command(cmd);
			bytes_returned = sizeof(command_t);
			status = STATUS_SUCCESS;
		}
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes_returned;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS create_close_dispatch(PDEVICE_OBJECT device, PIRP irp) {
	UNREFERENCED_PARAMETER(device);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS driver_initialize(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING device_name;
	RtlInitUnicodeString(&device_name, DEVICE_NAME);
	RtlInitUnicodeString(&g_symlink_name, SYMLINK_NAME);

	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name,
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&g_symlink_name, &device_name);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(g_device_object);
		return status;
	}

	driver_object->MajorFunction[IRP_MJ_CREATE] = create_close_dispatch;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = create_close_dispatch;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctl_dispatch;

	g_device_object->Flags |= DO_BUFFERED_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	init_hook();

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS driver_entry(void* driver_base, uint64_t driver_size) {
	UNREFERENCED_PARAMETER(driver_base);
	UNREFERENCED_PARAMETER(driver_size);

	return IoCreateDriver(nullptr, driver_initialize);
}
