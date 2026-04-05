#pragma once
#include <cstdint>
#include <vector>

class ExceptionFixer {
public:
	static uint32_t Fix(uint8_t* Buffer, uint64_t BufferSize);

private:
	static uint64_t RvaToOffset(uint8_t* Buffer, uint64_t Rva);
};
