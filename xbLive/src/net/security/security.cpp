#include "security.h"

void Security::RC4(unsigned char* pbKey, unsigned int cbKey, unsigned char* pbInpOut, unsigned int cbInpOut, unsigned int startOffset) {
	unsigned char s[256];
	unsigned char k[256];
	unsigned char temp;
	int i, j;

	for (i = 0; i < 256; i++) {
		s[i] = (unsigned char)i;
		k[i] = pbKey[i % cbKey];
	}

	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
	}

	i = j = 0;
	for (unsigned int x = startOffset; x < cbInpOut; x++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		int t = (s[i] + s[j]) % 256;
		pbInpOut[x] ^= s[t];
	}
}

void Security::EncryptKeys(EncryptionStruct* data) {
	data->iKey1 ^= 0x18762;
	data->iKey1 += 1337;
	data->iKey1 -= 0x10;
	data->iKey1 ^= 0x10;
	data->iKey1 += 0x11;
	data->iKey1 ^= 0x49471;
	data->iKey1 ^= 0x7a145 << 8;
	data->iKey1 += 0x22;
	data->iKey1 ^= 0x12;
	data->iKey1++;
	data->iKey1 ^= (0x88 + 0x9c + 0x15) - 1;
	data->iKey1 += 88;
	data->iKey1 ^= 2;
	data->iKey1 -= 2;
	data->iKey1 += 3;
	data->iKey1 ^= (0x15 << 16) + 1337;
	data->iKey1 ^= (((0x35 + 0x16) - 4) + 2334) * -1;
	data->iKey1 *= -1;

	data->iKey2 ^= 12;
	data->iKey2 += 0x55 << 4;
	data->iKey2 ^= 1337;
	data->iKey2 += 12;
	data->iKey2 ^= 99;
	data->iKey2 += 0x7a20f;
	data->iKey2 -= 0x49407;
	data->iKey2 ^= 0x45;
	data->iKey2 ^= 0xFFFF;
	data->iKey2 += 0xFF;
	data->iKey2 -= 0x12;
	data->iKey2 ^= 0x123;
	data->iKey2 ^= 3;
	data->iKey2 ^= 23;
	data->iKey2 ^= 1212;
	data->iKey2 ^= 9;
	data->iKey2 += 12;
	data->iKey2 += 89;
	data->iKey2 += data->iKey1 ^ 12;
	data->iKey2 ^= data->iKey1 - 100;
	data->iKey2 += data->iKey1 ^ 13;
	data->iKey2 += data->iKey1 ^ 14;
	data->iKey2 += data->iKey1 ^ 15;
	data->iKey2 += data->iKey1 ^ 16;
	data->iKey2 += data->iKey1 ^ 17;
	data->iKey2 ^= (data->iKey1 ^ data->iKey1) + (data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey1 << 8);
	data->iKey2 ^= (data->iKey1 ^ data->iKey1) + (data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey1 << 16);
}

void Security::EncryptHash(EncryptionStruct* data) {
	data->iHash -= 1000000000;
	data->iHash ^= 69696969;
	data->iHash += 123;
	data->iHash ^= (data->iKey1 << 2);
	data->iHash -= 1000;
	data->iHash += (data->iKey2 << 24) ^ 13;
	data->iHash -= (data->iKey2 / 2);
	data->iHash += (data->iKey1 ^ 1234);
	data->iHash ^= data->iKey2;
	data->iHash += data->iKey1;
	data->iHash ^= 111111;
	data->iHash ^= 121212;
	data->iHash ^= 131313;
	data->iHash ^= 141414;
	data->iHash ^= 151515;
	data->iHash ^= 161616;
	data->iHash ^= 171717;
	data->iHash ^= 181818;
	data->iHash ^= 191919;
	data->iHash--;
	data->iHash += 2;
	data->iHash ^= (data->iKey1 * 2);
	data->iHash ^= (data->iKey2 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 8);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 16);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey2 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey2 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 16);
	data->iHash ^= (data->iKey2 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 8);
	data->iHash ^= (data->iKey2 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 4);
	data->iHash ^= (data->iKey1 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 2);
	
	for (int i = 0; i < 0x10; i++) {
		data->iHash ^= (data->szRandomKey[i] ^ data->szRC4Key[i]);
	}
}

void Security::GenerateKeys(EncryptionStruct* data, Header* header) {
	memcpy(data->szRandomKey, header->Encryption.szRandomKey, 0x10);
	Utils::GenerateRandomBytes(data->szRC4Key, 0x10);

	data->iTime = Utils::GetTimeStamp();
	data->iHash = data->iTime;
	data->iKey1 = (rand() % 1000) + 1;
	data->iKey2 = (rand() % 1000) + 1;
}

EncryptionStruct* Security::CreateEncryption(BinaryWriter* writer, Header* header) {
	EncryptionStruct* enc = (EncryptionStruct*)Utils::Alloc(sizeof(EncryptionStruct));
	GenerateKeys(enc, header);
	EncryptHash(enc);
	EncryptKeys(enc);

	writer->WriteBytes(enc->szRandomKey, 0x10);
	writer->WriteBytes(enc->szRC4Key, 0x10);
	writer->WriteInt32(enc->iKey1);
	writer->WriteInt32(enc->iKey2);
	writer->WriteInt32(enc->iHash);

	return enc;
}

void Security::SendPacket(Socket serverWriter, unsigned char* data, unsigned int len, EncryptionStruct* enc) {
	if (len > ENCRYPTION_STRUCT_SIZE) {
		int salt = enc->iTime + 1337;
		auto converted = Utils::IntToBytes(salt);

		for (unsigned int i = ENCRYPTION_STRUCT_SIZE; i < len; i++) {
			data[i] = data[i] ^ (unsigned char)converted[0];
			data[i] = data[i] ^ (unsigned char)converted[1];
			data[i] = data[i] ^ (unsigned char)converted[2];
			data[i] = data[i] ^ (unsigned char)converted[3];
			
			for (int j = 0; j < 0x10; j++) {
				data[i] = data[i] ^ enc->szRandomKey[j];
			}
		}

		RC4(enc->szRC4Key, 0x10, data, len, ENCRYPTION_STRUCT_SIZE);
	}
	
	free(enc);

	serverWriter.Send(data, len);
}