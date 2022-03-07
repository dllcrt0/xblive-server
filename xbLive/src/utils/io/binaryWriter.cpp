#include "binaryWriter.h"

BinaryWriter::BinaryWriter(unsigned char* pData, unsigned int dwMaxSize, eEndian style) {
	pBuffer = pData;
	dwSize = dwMaxSize;
	Style = style;
	dwCurrentIndex = 0;
}

void BinaryWriter::Clean() {
	for (std::size_t i = 0; i < vAllocations.size(); i++) {
		free(vAllocations[i]);
		vAllocations.erase(vAllocations.begin() + i);
	}
}

void BinaryWriter::Reverse(unsigned char* arr, unsigned int dwSize) {
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

bool BinaryWriter::CanWrite(int size) {
	if ((dwCurrentIndex + size) > dwSize) {
		printf("[-] Can't write %i, current index is at end\n", size);
		return false;
	}

	return true;
}

void BinaryWriter::RegisterAllocation(void* pAllocation) {
	vAllocations.push_back(pAllocation);
}

void BinaryWriter::WriteDouble(double value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteInt16(short value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteUInt16(ushort value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteInt32(int value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteUInt32(unsigned int value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteInt64(int64_t value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteUInt64(uint64_t value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteFloat(float value) {
	if (CanWrite(sizeof(value))) {
		unsigned char* arr = (unsigned char*)malloc(sizeof(value));
		RegisterAllocation(arr);

		memcpy(arr, &value, sizeof(value));

		if (Style == eEndian::BigEndian) {
			Reverse(arr, sizeof(value));
		}

		memcpy((pBuffer + dwCurrentIndex), arr, sizeof(value));

		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteByte(unsigned char value) {
	if (CanWrite(sizeof(value))) {
		*(unsigned char*)(pBuffer + dwCurrentIndex) = value;
		dwCurrentIndex += sizeof(value);
	}
}

void BinaryWriter::WriteBytes(unsigned char* bytes, int size) {
	if (CanWrite(size)) {
		memcpy(pBuffer + dwCurrentIndex, bytes, size);
		dwCurrentIndex += size;
	}
}