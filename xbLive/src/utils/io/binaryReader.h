#ifndef BINARY_READER_H
#define BINARY_READER_H
#include <vector>
#include <stack>
#include <cstring>
#include "utils/structs.h"

class BinaryReader {
public:
	BinaryReader(unsigned char* pData, unsigned int dwMaxSize, eEndian style = BigEndian);
	bool CanRead(int size);
	void Clean();
	void Reverse(unsigned char* arr, unsigned int dwSize);

	double ReadDouble();
	short ReadInt16();
	ushort ReadUInt16();
	int ReadInt24();
	int ReadInt32();
	unsigned int ReadUInt32();
	int64_t ReadInt64();
	unsigned long long ReadUInt64();
	float ReadFloat();
	unsigned char ReadByte();
	bool ReadBool();
	char* ReadChars(int size);
	unsigned char* ReadBytes(int size);

	void CopyBytes(void* dest, int size);
private:
	unsigned char* pBuffer;
	unsigned int dwSize;
	unsigned long long dwCurrentIndex;
	eEndian Style;
	std::vector<void*> vAllocations;

	void RegisterAllocation(void* pAllocation);
};

#endif