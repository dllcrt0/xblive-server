#include "packetXOSC.h"

typedef struct _CONSOLE_PUBLIC_KEY {
	unsigned char PublicExponent[0x4]; // 0x0 sz:0x4
	unsigned char Modulus[0x80]; // 0x4 sz:0x80
} CONSOLE_PUBLIC_KEY, * PCONSOLE_PUBLIC_KEY; // size 132
typedef struct _XE_CONSOLE_ID {
	union {
		struct {
			unsigned char refurbBits : 4;
			unsigned char ManufactureMonth : 4;
			unsigned int ManufactureYear : 4;
			unsigned int MacIndex3 : 8;
			unsigned int MacIndex4 : 8;
			unsigned int MacIndex5 : 8;
			unsigned int Crc : 4;
		} asBits;
		unsigned char abData[5];
	};
} XE_CONSOLE_ID, * PXE_CONSOLE_ID; // size 5
typedef struct _XE_CONSOLE_CERTIFICATE {
	short CertSize; // 0x0 sz:0x2
	XE_CONSOLE_ID ConsoleId; // 0x2 sz:0x5
	unsigned char ConsolePartNumber[0xB]; // 0x7 sz:0xB
	unsigned char Reserved[0x4]; // 0x12 sz:0x4
	short Privileges; // 0x16 sz:0x2
	unsigned int ConsoleType; // 0x18 sz:0x4
	char ManufacturingDate[0x8]; // 0x1C sz:0x8
	CONSOLE_PUBLIC_KEY ConsolePublicKey; // 0x24 sz:0x84
	unsigned char Signature[0x100]; // 0xA8 sz:0x100
} XE_CONSOLE_CERTIFICATE, * PXE_CONSOLE_CERTIFICATE; // size 424
typedef union _INQUIRY_DATA {
	struct {
		unsigned char DeviceType : 5;
		unsigned char DeviceTypeQualifier : 3;
		unsigned char DeviceTypeModifier : 7;
		unsigned char RemovableMedia : 1;
		unsigned char Versions : 8;
		unsigned char ResponseDataFormat : 4;
		unsigned char HiSupport : 1;
		unsigned char NormACA : 1;
		unsigned char ReservedBit : 1;
		unsigned char AERC : 1;
		unsigned char AdditionalLength : 8;
		short Reserved : 16;
		unsigned char SoftReset : 1;
		unsigned char CommandQueue : 1;
		unsigned char Reserved2 : 1;
		unsigned char LinkedCommands : 1;
		unsigned char Synchronous : 1;
		unsigned char Wide16Bit : 1;
		unsigned char Wide32Bit : 1;
		unsigned char RelativeAddressing : 1;
		unsigned char VendorId[8];
		unsigned char ProductId[16];
		unsigned char ProductRevisionLevel[4];
	};
	unsigned char Data[0x24];
} INQUIRY_DATA, * PINQUIRY_DATA;
typedef struct _XECRYPT_RSA {
	unsigned int cqw; // 0x0 sz:0x4
	unsigned int dwPubExp; // 0x4 sz:0x4
	uint64_t qwReserved; // 0x8 sz:0x8
} XECRYPT_RSA, * PXECRYPT_RSA; // size 16
typedef struct _XECRYPT_RSAPUB_2048 {
	XECRYPT_RSA Rsa; // 0x0 sz:0x10
	uint64_t aqwM[0x20]; // 0x10 sz:0x100
} XECRYPT_RSAPUB_2048, * PXECRYPT_RSAPUB_2048; // size 272
typedef struct _XEIKA_ODD_DATA {
	unsigned char         Version;
	unsigned char         PhaseLevel;
	INQUIRY_DATA InquiryData;
} XEIKA_ODD_DATA, * PXEIKA_ODD_DATA;
typedef struct _XEIKA_DATA {
	XECRYPT_RSAPUB_2048 PublicKey;
	unsigned int               Signature;
	short                Version;
	XEIKA_ODD_DATA      OddData;
	unsigned char                Padding[4];
} XEIKA_DATA, * PXEIKA_DATA;
typedef struct _XEIKA_CERTIFICATE {
	short       Size;
	XEIKA_DATA Data;
} XEIKA_CERTIFICATE, * PXEIKA_CERTIFICATE;

unsigned char fuses[7][0x10] = {
	{ 0xc0, 0xdc, 0xfe, 0xf3, 0xd7, 0x3e, 0xed, 0x7e, 0x5a, 0xf8, 0xb1, 0xbb, 0xb2, 0xe0, 0x26, 0x95 }, // Xenon
	{ 0x96, 0x23, 0x74, 0x9c, 0x9e, 0xc5, 0x2b, 0x30, 0xc6, 0x68, 0x05, 0x9e, 0xad, 0x9c, 0x12, 0xa8 }, // Zephyr
	{ 0x82, 0xc1, 0xf0, 0x00, 0x9e, 0x79, 0x97, 0xf3, 0x34, 0x0e, 0x01, 0x45, 0x1a, 0xd0, 0x32, 0x57 }, // Falcon
	{ 0x3a, 0x5b, 0x47, 0xd6, 0xdd, 0x5a, 0xf8, 0x66, 0x93, 0xed, 0x05, 0x47, 0x25, 0x66, 0x15, 0x69 }, // Jasper
	{ 0xdb, 0xe6, 0x35, 0x87, 0x78, 0xcb, 0xfc, 0x2f, 0x52, 0xa3, 0xba, 0xf8, 0x92, 0x45, 0x8d, 0x65 }, // Trinity
	{ 0xd1, 0x32, 0xfb, 0x43, 0x9b, 0x48, 0x47, 0xe3, 0x9f, 0xe5, 0x46, 0x46, 0xf0, 0xa9, 0x9e, 0xb1 }, // Corona
	{ 0xd1, 0x32, 0xfb, 0x43, 0x9b, 0x48, 0x47, 0xe3, 0x9f, 0xe5, 0x46, 0x46, 0xf0, 0xa9, 0x9e, 0xb1 }  // Winchester
};

int GetMotherboardIndex(unsigned char* cert) {
	int moboSerialByte = 0;

	auto kv = (_XE_CONSOLE_CERTIFICATE*)cert;

	moboSerialByte = (((Utils::CharToByte(kv->ConsolePartNumber[2]) << 4) & 0xF0) | ((Utils::CharToByte(kv->ConsolePartNumber[3]) & 0x0F)));

	if (moboSerialByte < 0x10)
		moboSerialByte = 0;

	else if (moboSerialByte < 0x14)
		moboSerialByte = 1;

	else if (moboSerialByte < 0x18)
		moboSerialByte = 2;

	else if (moboSerialByte < 0x52)
		moboSerialByte = 3;

	else if (moboSerialByte < 0x58)
		moboSerialByte = 4;
	else
		moboSerialByte = 5;

	return moboSerialByte;
}

void PacketXOSC::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketXOSC");

	bool good = true;
	ClientInfo client;
	ClientEndPoint endPoint;
	unsigned char resp[0x2C8 + 4 + ENCRYPTION_STRUCT_SIZE];
	unsigned char kv_xeIkaCertificateInquiryData[0x24]; // done
	unsigned char kv_consoleSerialNumber[0xC]; // done
	unsigned char kv_consoleCertificateAbData[0x5]; // done
	unsigned char cpuKeyDigest[0x10]; // done
	unsigned char cpuKeyDigestOut[0x14];
	unsigned char xosc[0x2C8];

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	int64_t hvProtectedFlags = reader.ReadInt64();
	int motherboardIndex = reader.ReadInt32(); // done
	reader.CopyBytes(kv_xeIkaCertificateInquiryData, 0x24); // done
	reader.CopyBytes(kv_consoleSerialNumber, 0xC); // done
	reader.CopyBytes(kv_consoleCertificateAbData, 0x5); // done
	reader.CopyBytes(cpuKeyDigest, 0x10); // done
	uint16_t kv_oddFeatures = reader.ReadUInt16(); // done
	bool typeOneKv = reader.ReadBool(); // done
	unsigned int kv_policyFlashSize = reader.ReadUInt32(); // done
	bool fcrt = reader.ReadBool(); // done
	unsigned int titleID = reader.ReadUInt32();
	unsigned int mediaID = reader.ReadUInt32();
	reader.CopyBytes(xosc, sizeof(xosc));

	if (motherboardIndex < 0 || motherboardIndex > 6) {
		Log::Error(header, serverWriter, "PacketXOSC", "Motherboard index is out of range");
		good = false;
		goto end;
	}

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client)) {
		pMySQL.IncrementChallengeCount(Utils::BytesToString(header->szConsoleKey, 0x14).c_str());

		/*if (client.iTimeEnd < Utils::GetTimeStamp() && client.iReserveSeconds == 0 && !bFreemode) {
			good = false;
			goto end;
		}*/
	}

	if (!pMySQL.GetClientEndPoint(Utils::BytesToString(header->szToken, 0x20).c_str(), &endPoint)) {
		Log::Error(header, serverWriter, "PacketXOSC", "Failed to get client data");
		good = false;
		goto end;
	}

	if (endPoint.bUsingNoKV) {
		// read data and replace the data
		std::string location = Utils::GetCurrentPath() + "/Server Data/KVs/" + client.strNoKVHash + "/";
		if (!Utils::DirectoryExists(location.c_str())) {
			Log::Error(header, serverWriter, "PacketXOSC", "Using no KV mode but cpukey.txt wasn't found for " + client.strNoKVHash);
			goto end;
		}

		std::ifstream file = std::ifstream(location + "kv.bin", std::ios::binary | std::ios::ate);
		int size = (int)file.tellg();
		file.seekg(0, std::ios::beg);

		if (size < 0xC00) {
			Log::Error(header, serverWriter, "PacketXOSC", client.strNoKVHash + " size is below 0xC00");
			goto end;
		}

		std::vector<char> buffer = std::vector<char>(0x1EFF);
		if (file.read(buffer.data(), 0x1EFF)) {
			file.close();

			FILE* fp = fopen((location + "cpukey.txt").c_str(), "rb");
			if (fp) {
				unsigned char v[0x20];
				fread(v, 0x20, 1, fp);
				fclose(fp);

				for (int i = 0, b = 0; i < 0x20; i += 2, b++) {
					cpuKeyDigest[i == 0 ? 0 : (i / 2)] = (unsigned char)(((Utils::CharToByte(v[i]) << 4) & 0xF0) | ((Utils::CharToByte(v[i + 1]) & 0x0F)));
				}

				CSHA1 sha;
				sha.Update(cpuKeyDigest, 0x10);
				sha.Final();
				sha.GetHash(cpuKeyDigestOut);
				memcpy(cpuKeyDigest, cpuKeyDigestOut, 0x10);
			
				motherboardIndex = GetMotherboardIndex((unsigned char*)(buffer.data()) + 0x9C8);

				XEIKA_CERTIFICATE* xeika = (XEIKA_CERTIFICATE*)(buffer.data() + 0xB70);
				memcpy(kv_xeIkaCertificateInquiryData, (void*)&xeika->Data.OddData.InquiryData, 0x24);

				XE_CONSOLE_CERTIFICATE* cert = (XE_CONSOLE_CERTIFICATE*)(buffer.data() + 0x9C8);
				memcpy(kv_consoleCertificateAbData, cert->ConsoleId.abData, 5);

				memcpy(kv_consoleSerialNumber, buffer.data() + 0xB0, 0xC);
				memcpy(&kv_oddFeatures, buffer.data() + 0x1C, 0x2);
				memcpy(&kv_policyFlashSize, buffer.data() + 0x24, 0x4);

				fcrt = (kv_oddFeatures & 0x120) != 0;

				typeOneKv = true;
				for (int i = 0; i < 256; ++i) {
					if ((buffer.data() + 0x1DF8)[i] != 0) {
						typeOneKv = false;
						break;
					}
				}

				buffer.clear();
			} else {
				Log::Error(header, serverWriter, "PacketXOSC", client.strNoKVHash + "/cpukey.txt" + " can't be opened");
				goto end;
			}
		} else {
			Log::Error(header, serverWriter, "PacketXOSC", client.strNoKVHash + " can't be opened");
			goto end;
		}
	}

	memcpy(xosc + 0x70, fuses[motherboardIndex], 0x10);
	memcpy(xosc + 0x50, cpuKeyDigest, 0x10);
	memcpy(xosc + 0xF0, kv_xeIkaCertificateInquiryData, 0x24);
	memcpy(xosc + 0x114, kv_xeIkaCertificateInquiryData, 0x24);
	memcpy(xosc + 0x138, kv_consoleSerialNumber, 0xC);

	for (int i = 0; i < 0x30; i++) { xosc[0x1A0 + i] = 0x0; }

	memcpy(xosc + 0x1A0, kv_consoleCertificateAbData, 0x5);

	for (int i = 0; i < 0x14; i++) { xosc[0x1D4 + i] = 0x0; }
	for (int i = 0; i < 0x8; i++) { xosc[0x1E8 + i] = 0x0; }
	for (int i = 0; i < 0x28; i++) { xosc[0x1F0 + i] = 0x0; }
	for (int i = 0; i < 0x4; i++) { xosc[0x218 + i] = 0x0; }

	unsigned char kv_oddFeaturesBytes[2];
	Utils::GetBytes<ushort>(kv_oddFeaturesBytes, kv_oddFeatures, 2); writer.Reverse(kv_oddFeaturesBytes, 2);
	memcpy(xosc + 0x14A, kv_oddFeaturesBytes, 2);

	for (int i = 0; i < 0x8; i++) { xosc[0x180 + i] = 0x0; }

	if (typeOneKv) {
		memset(xosc + 0x150, 0x0, 0x4);
	} else {
		unsigned char policyFlashSize[4];
		Utils::GetBytes<unsigned int>(policyFlashSize, kv_policyFlashSize, 4); writer.Reverse(policyFlashSize, 2);
		memcpy(xosc + 0x150, policyFlashSize, 0x4);
	}

	unsigned char number6[4];
	Utils::GetBytes<int>(number6, 6, 4); writer.Reverse(number6, 0x4);
	memcpy(xosc + 0x2C4, number6, 0x4);

	unsigned char _1bf[8];
	Utils::GetBytes<int64_t>(_1bf, (int64_t)0x00000000000001BF, 0x8); writer.Reverse(_1bf, 0x8);
	memcpy(xosc + 0x08, _1bf, 0x8);

	unsigned char _40000012[4];
	Utils::GetBytes<int>(_40000012, 0x40000012, 4); writer.Reverse(_40000012, 4);
	memcpy(xosc + 0x34, _40000012, 0x4);

	unsigned char _d83e[2];
	Utils::GetBytes<unsigned short>(_d83e, 0xD83E, 2); writer.Reverse(_d83e, 2);
	memcpy(xosc + 0x146, _d83e, 0x2);

	unsigned char fcrtShit[4];
	Utils::GetBytes<int>(fcrtShit, fcrt ? 0x033389D3 : 0x023389D3, 4); writer.Reverse(fcrtShit, 4);
	memcpy(xosc + 0x158, fcrtShit, 0x4);

	unsigned char _40000207[4];
	Utils::GetBytes<int>(_40000207, 0x40000207, 4); writer.Reverse(_40000207, 4);
	memcpy(xosc + 0x1D0, _40000207, 0x4);

	if (!typeOneKv) {
		unsigned char _00033840[4];
		Utils::GetBytes<int>(_00033840, 0x00033840, 4); writer.Reverse(_00033840, 4);
		memcpy(xosc + 0x2B4, _00033840, 0x4);
	}

	unsigned char _00200000[4];
	Utils::GetBytes<int>(_00200000, 0x00200000, 4); writer.Reverse(_00200000, 4);
	memcpy(xosc + 0x2B8, _00200000, 0x4);

	if (titleID == 0 || titleID == 0xFFFFFFFF || mediaID == 0xFFFFFFFF || titleID == 0xFFFF0055 || titleID == 0xFFFE07FF || titleID == 0xF5D10000) {
		titleID = 0xFFFE07D1;

		memset(xosc + 0x84, 0x0, 0x4);

		unsigned char _FFFE07D1[4];
		Utils::GetBytes<unsigned int>(_FFFE07D1, 0xFFFE07D1, 4); writer.Reverse(_FFFE07D1, 4);
		memcpy(xosc + 0x88, _FFFE07D1, 0x4);
	}

	if (titleID != 0xFFFE07D1) {
		hvProtectedFlags = 4 | (hvProtectedFlags);
	} else {
		hvProtectedFlags = 4 | (hvProtectedFlags & 1);
	}

	unsigned char hvProtectedFlagsBytes[8];
	Utils::GetBytes<int64_t>(hvProtectedFlagsBytes, hvProtectedFlags, 8); writer.Reverse(hvProtectedFlagsBytes, 8);
	memcpy(xosc + 0x198, hvProtectedFlagsBytes, 0x8);

end:
	auto encryption = Security::CreateEncryption(&writer, header);
	
	writer.WriteInt32((int)(good ? RESPONSE_SUCCESS : RESPONSE_ERROR));
	if (good) writer.WriteBytes(xosc, sizeof(xosc));
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}