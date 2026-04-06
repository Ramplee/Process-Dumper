#pragma once
#pragma warning (disable: 4003)
#include "../driver/driver_um_lib.hpp"

namespace process {

    /// Flag indicating if the process API has been initialized.
    inline bool inited = false;

    // Owner specific data
    /// The Process ID (PID) of the owner (current) process.
    inline uint64_t owner_pid = 0;

    /// The CR3 register value for the owner process.
    inline uint64_t owner_cr3 = 0;

    // Target specific data
    /// Name of the target process to interact with.
    inline std::string target_process_name;

    /// The PID of the target process.
    inline uint64_t target_pid = 0;

    /// The CR3 register value for the target process.
    inline uint64_t target_cr3 = 0;

    /// The number of modules loaded in the target process.
    inline uint64_t target_module_count = 0;

    /// A pointer to the array of target process module information.
    inline module_info_t* target_modules = 0;

    /**
     * @brief Initializes the process API by gathering relevant data for the target process.
     *
     * This function retrieves the PID, CR3, and module information of the target process
     * and initializes the process API. It also ensures that the Roseware driver is initialized.
     *
     * @param process_name The name of the target process to initialize.
     * @return true if initialization is successful, false otherwise.
     */
    inline bool init_process(std::string process_name) {

        target_process_name = process_name;

        if (!ioctl::init_roseware_lib()) {
            return false;
        }

        if (!ioctl::is_lib_inited()) {
            log("Can't init process if the rose instance is not initialized");
            return false;
        }

        owner_pid = GetCurrentProcessId();
        if (!owner_pid) {
            log("Failed to get pid of owner process");
            return false;
        }

        owner_cr3 = ioctl::get_cr3(owner_pid);
        if (!owner_cr3) {
            log("Failed to get cr3 of owner process");
            return false;
        }

        target_pid = ioctl::get_pid_by_name(process_name.c_str());
        if (!target_pid) {
            log("Failed to get pid of target process: %s", process_name.c_str());
            return false;
        }

        target_cr3 = ioctl::get_cr3(target_pid);
        if (!target_cr3) {
            log("Failed to get initial CR3 for target process");
            return false;
        }

        target_module_count = ioctl::get_ldr_data_table_entry_count(target_pid);
        if (!target_module_count) {
            log("Failed get target module count");
            return false;
        }

        target_modules = (module_info_t*)malloc(sizeof(module_info_t) * target_module_count);
        if (!target_modules) {
            log("Failed to alloc memory for modules");
            return false;
        }

        // Ensure that the memory is present (mark pte as present)
        memset(target_modules, 0, sizeof(module_info_t) * target_module_count);

        if (!ioctl::get_data_table_entry_info(target_pid, target_modules)) {
            log("Failed getting data table entry info");
            return false;
        }

        inited = true;

        return true;
    }

    /**
     * @brief Attempts to attach to the specified target process by initializing it.
     *
     * This function internally calls `init_process` to initialize the target process by gathering
     * necessary data such as PID, CR3, and module information. It serves as a simplified interface
     * to initialize the process without directly calling `init_process`.
     *
     * @param process_name The name of the process to attach to.
     * @return true if the process was successfully initialized and attached, false otherwise.
     */
    inline bool attach_to_proc(std::string process_name) {
        return init_process(process_name);
    }

    /**
     * @brief Reads data from the target process's memory.
     *
     * Copies data from the specified memory address in the target process to a local buffer.
     *
     * @tparam t The type of data to read.
     * @param src The source address in the target process.
     * @param size The number of bytes to read (default is the size of the type `t`).
     * @return The data read from memory. Returns an empty object if the read fails.
     */
    template <typename t>
    inline t read(void* src, uint64_t size = sizeof(t)) {
        t buffer{};

        if (!ioctl::copy_virtual_memory(target_pid, owner_pid, src, &buffer, size))
            return {};

        return buffer;
    }

    /**
     * @brief Writes data to the target process's memory.
     *
     * Copies data from a local buffer to a specified memory address in the target process.
     *
     * @param dest The destination address in the target process.
     * @param src The source buffer to copy from.
     * @param size The number of bytes to write.
     * @return true if the write is successful, false otherwise.
     */
    inline bool write(void* dest, void* src, uint64_t size) {

        if (!ioctl::copy_virtual_memory(owner_pid, target_pid, src, dest, size))
            return false;

        return true;
    }

    /**
     * @brief Reads an array of data from the target process's memory.
     *
     * Copies an array of data from the target process's memory to a local buffer.
     *
     * @param dest The destination buffer to store the data.
     * @param src The source memory address in the target process.
     * @param size The total size of the data to read.
     * @return true if the read operation is successful, false otherwise.
     */
    inline bool read_array(void* dest, void* src, uint64_t size) {
        if (!ioctl::copy_virtual_memory(target_pid, owner_pid, src, dest, size))
            return false;

        return true;
    }

    /**
     * @brief Writes an array of data to the target process's memory.
     *
     * Copies an array of data from a local buffer to the target process's memory.
     *
     * @param dest The destination memory address in the target process.
     * @param src The source buffer to copy from.
     * @param size The total size of the data to write.
     * @return true if the write operation is successful, false otherwise.
     */
    inline bool write_array(void* dest, void* src, uint64_t size) {

        if (!ioctl::copy_virtual_memory(owner_pid, target_pid, src, dest, size))
            return false;

        return true;
    }

    /**
     * @brief Retrieves information about a module loaded in the target process.
     *
     * Searches for the specified module by name in the target process and returns its information.
     *
     * @param module_name The name of the module to search for.
     * @return A module_info_t structure containing information about the module.
     *         Returns an empty module_info_t if not found.
     */
    inline module_info_t get_module(std::string module_name) {
        for (uint64_t i = 0; i < target_module_count - 1; i++) {

            if (strstr(module_name.c_str(), target_modules[i].name)) {
                return target_modules[i];
            }
        }

        return { 0 };
    }

    /**
     * @brief Retrieves the base address of a module loaded in the target process.
     *
     * Searches for the module and returns its base address.
     *
     * @param module_name The name of the module to search for.
     * @return The base address of the module, or 0 if not found.
     */
    inline uint64_t get_module_base(std::string module_name) {
        module_info_t module = get_module(module_name);
        return module.base;
    }

    /**
     * @brief Retrieves the size of a module loaded in the target process.
     *
     * Searches for the module and returns its size.
     *
     * @param module_name The name of the module to search for.
     * @return The size of the module, or 0 if not found.
     */
    inline uint64_t get_module_size(std::string module_name) {
        module_info_t module = get_module(module_name);
        return module.size;
    }

    /**
     * @brief Logs the names of all modules loaded in the target process.
     *
     * Iterates over the list of loaded modules and logs each module's name.
     */
    inline void log_modules(void) {
        for (uint64_t i = 0; i < target_module_count - 1; i++) {
            log("%s", target_modules[i].name);
        }
    }

    /**
     * @brief Retrieves the PID of a process by its name.
     *
     * Searches for a process by name and returns its PID.
     *
     * @param process_name The name of the process.
     * @return The PID of the process, or 0 if the process could not be found.
     */
    inline uint64_t get_pid(std::string process_name) { return ioctl::get_pid_by_name(process_name.c_str()); }

};
