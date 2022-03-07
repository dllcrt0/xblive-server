#include "binaryReader.h"

BinaryReader::BinaryReader(unsigned char* pData, unsigned int dwMaxSize, eEndian style) {
	pBuffer = pData;
	dwSize = dwMaxSize;
	Style = style;
	dwCurrentIndex = 0;
}

void BinaryReader::Clean() {
	for (std::size_t i = 0; i < vAllocations.size(); i++) {
		free(vAllocations[i]);
		vAllocations.erase(vAllocations.begin() + i);
	}
}

void BinaryReader::Reverse(unsigned char* arr, unsigned int dwSize) {
	std::stack<unsigned char> stack;

	for (unsigned int i = 0; i < dwSize; i++) {
		stack.push(arr[i]);
	}

	int index = 0;

	while (!stack.empty()) {
		arr[index++] = stack.top();
		stack.pop();
	}
}

bool BinaryReader::CanRead(int size) {
	if ((dwCurrentIndex + size) > dwSize) {
		printf("[-] Can't read %i, current index is at end\n", size);
		return false;
	}

	return true;
}

void BinaryReader::RegisterAllocation(void* pAllocation) {
	vAllocations.push_back(pAllocation);
}

unsigned char BinaryReader::ReadByte() {
	if (CanRead(sizeof(unsigned char))) {
		unsigned char ret = *(unsigned char*)(pBuffer + dwCurrentIndex);
		dwCurrentIndex += sizeof(unsigned char);
		return ret;
	}

	return 0;
}

bool BinaryReader::ReadBool() {
	if (CanRead(sizeof(bool))) {
		bool ret = *(bool*)(pBuffer + dwCurrentIndex);
		dwCurrentIndex += sizeof(bool);
		return ret;
	}

	return 0;
}

void BinaryReader::CopyBytes(void* dest, int size) {
	auto buffer = ReadBytes(size);
	if (buffer) {
		memcpy(dest, buffer, size);
	}
}

unsigned char* BinaryReader::ReadBytes(int size) {
	if (CanRead(size)) {
		unsigned char* arr = (unsigned char*)malloc(size);
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), size);

		/*if (Style == eEndian::BigEndian) {
			Reverse(arr, size);
		}*/

		dwCurrentIndex += size;

		return arr;
	}

	return 0;
}

char* BinaryReader::ReadChars(int size) {
	if (CanRead(size)) {
		char* arr = (char*)malloc(size);
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), size);

		/*if (Style == eEndian::BigEndian) {
			Reverse(arr, size);
		}*/

		dwCurrentIndex += size;

		return arr;
	}

	return 0;
}

short BinaryReader::ReadInt16() {
	if (CanRead(sizeof(short))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(short));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(short));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(short));
		}

		dwCurrentIndex += sizeof(short);

		return *(short*)arr;
	}

	return 0;
}

ushort BinaryReader::ReadUInt16() {
	if (CanRead(sizeof(ushort))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(ushort));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(ushort));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(ushort));
		}

		dwCurrentIndex += sizeof(ushort);

		return *(ushort*)arr;
	}

	return 0;
}

double BinaryReader::ReadDouble() {
	if (CanRead(sizeof(double))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(double));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(double));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(double));
		}

		dwCurrentIndex += sizeof(double);

		return *(double*)arr;
	}

	return 0;
}

int BinaryReader::ReadInt24() {
	if (CanRead(3)) {
		unsigned char* arr = (unsigned char*)malloc(3);
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), 3);

		dwCurrentIndex += 3;

		if (Style == eEndian::BigEndian) {
			return (((arr[0] << 0x10) | (arr[1] << 8)) | arr[2]);
		}

		return (((arr[2] << 0x10) | (arr[1] << 8)) | arr[0]);
	}

	return 0;
}

int BinaryReader::ReadInt32() {
	if (CanRead(sizeof(int))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(int));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(int));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(int));
		}

		dwCurrentIndex += sizeof(int);

		return *(int*)arr;
	}

	return 0;
}

unsigned int BinaryReader::ReadUInt32() {
	if (CanRead(sizeof(unsigned int))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(unsigned int));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(unsigned int));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(unsigned int));
		}

		dwCurrentIndex += sizeof(unsigned int);

		return *(unsigned int*)arr;
	}

	return 0;
}

int64_t BinaryReader::ReadInt64() {
	if (CanRead(sizeof(int64_t))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(int64_t));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(int64_t));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(int64_t));
		}

		dwCurrentIndex += sizeof(int64_t);

		return *(long long*)arr;
	}

	return 0;
}

unsigned long long BinaryReader::ReadUInt64() {
	if (CanRead(sizeof(unsigned long long))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(unsigned long long));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(unsigned long long));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(unsigned long long));
		}

		dwCurrentIndex += sizeof(unsigned long long);

		return *(unsigned long long*)arr;
	}

	return 0;
}

float BinaryReader::ReadFloat() {
	if (CanRead(sizeof(float))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(float));
		RegisterAllocation(arr);

		memcpy(arr, (pBuffer + dwCurrentIndex), sizeof(float));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(float));
		}

		dwCurrentIndex += sizeof(float);

		return *(float*)arr;
	}

	return 0;
}