#include "packetGetKV.h"

struct ConsoleID {
	unsigned char refurbBits : 4;
	unsigned char ManufactureMonth : 4;
	unsigned int ManufactureYear : 4;
	unsigned int MacIndex3 : 8;
	unsigned int MacIndex4 : 8;
	unsigned int MacIndex5 : 8;
	unsigned int Crc : 4;
};

bool CompareLowestUses(KVs& first, KVs& second) {
	return first.iUses < second.iUses;
}

std::string CalculateBestKV(std::string missThisOne = "00000000") {
	std::vector<KVs> kvs = pMySQL.GetKVs();
	if (kvs.size()) {
		if (missThisOne != "00000000") {
			for (std::size_t i = 0; i < kvs.size(); i++) {
				if (kvs[i].strHash == missThisOne) {
					kvs.erase(kvs.begin() + i);
					break;
				}
			}
		}

		std::sort(kvs.begin(), kvs.end(), CompareLowestUses);
		return kvs[0].strHash;
	}

	return "00000000";
}

void PacketGetKV::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetKV");

	unsigned char resp[0x732 + ENCRYPTION_STRUCT_SIZE];

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));
	eResponseStatus status = RESPONSE_ERROR;

	unsigned char hash[0x4];
	unsigned char consoleObfuscationKey[0x10];
	unsigned char consolePrivateKey[0x1D0];
	unsigned char xeIkaPrivateKey[0x390];
	unsigned char consoleSerial[0xC];
	unsigned char consoleCert[0x1A8];
	unsigned char macAddress[0x6];
	ClientInfo clientInfo;

	int hashFindTimeout = 0;
	std::string ignoreThisHash = "00000000";

	bool refresh = reader.ReadBool();
	bool cond = (reader.ReadUInt32() & 0xF0000000) > 0x40000000;

	pMySQL.UpdateUsingKVEndpointStatus(Utils::BytesToString(header->szToken, 0x20).c_str(), true);

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &clientInfo)) {
		if (clientInfo.iTimeEnd < Utils::GetTimeStamp() && clientInfo.iReserveSeconds == 0 && !bFreemode) {
			Log::Error(header, serverWriter, "PacketGetKV", "Client doesn't have any time");
			status = RESPONSE_ERROR;
			goto end;
		}

		if (clientInfo.strNoKVHash == "00000000" || refresh) {
			// ALLOCATE A KV

			if (refresh) {
				// if it's not 0 and if it's been less than 6 hours
				if (clientInfo.iNoKVLastRefresh != 0 && (Utils::GetTimeStamp() - clientInfo.iNoKVLastRefresh) < 21600) {
					Log::Error(header, serverWriter, "PacketGetKV", "Trying to refresh KV too fast");
					status = RESPONSE_KV_TIMEOUT;
					goto end;
				}

				ignoreThisHash = clientInfo.strNoKVHash;
			}

		generate:
			hashFindTimeout++;
			std::string hash = CalculateBestKV(ignoreThisHash);
			std::string location = Utils::GetCurrentPath() + "/Server Data/KVs/" + hash + "/";
			if (!Utils::DirectoryExists(location.c_str())) {
				if (hashFindTimeout == 10) {
					Log::Error(header, serverWriter, "PacketGetKV", "Failed to generate a KV hash, no directories existed");
					goto end;
				}

				ignoreThisHash = hash;
				goto generate;
			}

			// assume it has a good kv hash now that exists
			pMySQL.UpdateClientNoKVHash(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), hash);
			pMySQL.IncrementKVUsesCount(hash);
			clientInfo.strNoKVHash = hash;
			status = RESPONSE_KV_NEW_ALLOCATED;

			if (refresh) {
				// update last time
				pMySQL.UpdateClientNoKVLastRefresh(Utils::BytesToString(header->szConsoleKey, 0x14).c_str());

				if (ignoreThisHash != "00000000") {
					// negate uses
					pMySQL.DecrementKVUsesCount(ignoreThisHash);
				}
			}

			goto finalloop;
		} else {
		finalloop:
			// HAS A KV
			std::string location = Utils::GetCurrentPath() + "/Server Data/KVs/" + clientInfo.strNoKVHash + "/";
			if (Utils::DirectoryExists(location.c_str())) {
				std::ifstream file = std::ifstream(location + "kv.bin", std::ios::binary | std::ios::ate);
				int size = (int)file.tellg();
				file.seekg(0, std::ios::beg);

				if (size < 0xB80) {
					Log::Error(header, serverWriter, "PacketGetKV", clientInfo.strNoKVHash + " size is below 0xA80");
					goto end;
				}

				std::vector<char> buffer = std::vector<char>(0xB80);
				if (file.read(buffer.data(), 0xB80)) {
					file.close();

					memcpy(hash, buffer.data(), 0x4);
					memcpy(consoleObfuscationKey, buffer.data() + 0xD0, 0x10);
					memcpy(consolePrivateKey, buffer.data() + 0x298, 0x1D0);
					memcpy(xeIkaPrivateKey, buffer.data() + 0x468, 0x390);
					memcpy(consoleSerial, buffer.data() + 0xB0, 0xC);
					memcpy(consoleCert, buffer.data() + 0x9C8, 0x1A8);
					buffer.clear();

					ConsoleID* cid = (ConsoleID*)(consoleCert + 2);
					macAddress[0] = cond ? 0x7C : 0x00;
					macAddress[1] = cond ? 0xED : 0x22;
					macAddress[2] = cond ? 0xD8 : 0x48;
					macAddress[3] = (unsigned char)cid->MacIndex3;
					macAddress[4] = (unsigned char)cid->MacIndex4;
					macAddress[5] = (unsigned char)cid->MacIndex5;

					// encrypt the cert so it isn't in our ram
					static unsigned char rc4Key[34] = {
						0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74,
						0x65, 0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20,
						0x6B, 0x76, 0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
					};

					Security::RC4(rc4Key, sizeof(rc4Key), consoleCert, 0x1A8);

					if (status != RESPONSE_KV_NEW_ALLOCATED)
						status = RESPONSE_SUCCESS;

					Log::Success(header, serverWriter, "PacketGetKV", clientInfo.strNoKVHash);
				} else {
					Log::Error(header, serverWriter, "PacketGetKV", clientInfo.strNoKVHash + " can't be opened");
					goto end;
				}
			} else {
				Log::Warn(header, serverWriter, "PacketGetKV", clientInfo.strNoKVHash + " directory doesn't exist, allocating a new KV");
				goto generate;
			}
		}
	}

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteBytes(hash, 0x4);
	writer.WriteBytes(consoleObfuscationKey, 0x10);
	writer.WriteBytes(consolePrivateKey, 0x1D0);
	writer.WriteBytes(xeIkaPrivateKey, 0x390);
	writer.WriteBytes(consoleSerial, 0xC);
	writer.WriteBytes(consoleCert, 0x1A8);
	writer.WriteBytes(macAddress, 0x6);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}