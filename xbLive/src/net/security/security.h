#ifndef SECURITY_H
#define SECURITY_H
#include <iostream>
#include "utils/io/binaryWriter.h"
#include "net/socket.h"

struct EncryptionStruct {
	unsigned char szRandomKey[0x10];
	unsigned char szRC4Key[0x10];
	int iKey1;
	int iKey2;
	unsigned int iHash;

	// enc only
	int iTime;
};

class Security {
public:
	static void RC4(unsigned char* pbKey, unsigned int cbKey, unsigned char* pbInpOut, unsigned int cbInpOut, unsigned int startOffset = 0);
	static void EncryptKeys(EncryptionStruct* data);
	static void EncryptHash(EncryptionStruct* data);
	static void GenerateKeys(EncryptionStruct* data, Header* header);
	static EncryptionStruct* CreateEncryption(BinaryWriter* writer, Header* header);
	static void SendPacket(Socket serverWriter, unsigned char* data, unsigned int len, EncryptionStruct* enc);
};

#endif