#ifndef BINARY_WRITER_H
#define BINARY_WRITER_H
#include <vector>
#include <stack>
#include <cstring>
#include "utils/structs.h"

class BinaryWriter {
public:
	BinaryWriter() {}
	BinaryWriter(unsigned char* pData, unsigned int dwMaxSize, eEndian style = BigEndian);
	bool CanWrite(int size);
	void Clean();
	void Reverse(unsigned char* arr, unsigned int dwSize);

	void WriteDouble(double value);
	void WriteInt16(short value);
	void WriteUInt16(ushort value);
	void WriteInt32(int value);
	void WriteUInt32(unsigned int value);
	void WriteInt64(int64_t value);
	void WriteUInt64(uint64_t value);
	void WriteFloat(float value);
	void WriteByte(unsigned char value);
	void WriteBytes(unsigned char* bytes, int size);
private:
	unsigned char* pBuffer;
	unsigned int dwSize;
	unsigned long long dwCurrentIndex;
	eEndian Style;
	std::vector<void*> vAllocations;

	void RegisterAllocation(void* pAllocation);
};


#endif