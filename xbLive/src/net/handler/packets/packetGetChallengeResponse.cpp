#include "packetGetChallengeResponse.h"

void PacketGetChallengeResponse::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetChallengeResponse");

	unsigned char resp[0x124 + ENCRYPTION_STRUCT_SIZE];

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	unsigned char challengeResp[0x120];
	memset(challengeResp, 0, 0x120);
	unsigned char sessionSalt[0x10];
	bool good = false;

	unsigned char hvsalt[0x10];
	reader.CopyBytes(hvsalt, 0x10);
	unsigned char kvcpu[0x10];
	reader.CopyBytes(kvcpu, 0x10);
	bool typeone = reader.ReadBool();
	bool fcrt = reader.ReadBool();
	bool crl = reader.ReadBool();

	memcpy(sessionSalt, header->szToken, 0x10);

	ClientEndPoint endPoint;
	ClientInfo client;

	if (!pMySQL.GetClientEndPoint(Utils::BytesToString(header->szToken, 0x20).c_str(), &endPoint)) {
		Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Failed to get client data");
		goto end;
	}

	pMySQL.IncrementRequestTokenChallengeCount(Utils::BytesToString(header->szToken, 0x20).c_str());

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client)) {
		pMySQL.IncrementChallengeCount(Utils::BytesToString(header->szConsoleKey, 0x14).c_str());

		if (endPoint.bUsingNoKV) {
			// read data and replace the data
			std::string location = Utils::GetCurrentPath() + "/Server Data/KVs/" + client.strNoKVHash + "/";
			if (!Utils::DirectoryExists(location.c_str())) {
				Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Using no KV mode but cpukey.txt wasn't found for " + client.strNoKVHash);
				goto end;
			}

			FILE* fp = fopen((location + "cpukey.txt").c_str(), "rb");
			if (fp) {
				unsigned char v[0x20];
				fread(v, 0x20, 1, fp);
				fclose(fp);

				for (int i = 0, b = 0; i < 0x20; i += 2, b++) {
					kvcpu[i == 0 ? 0 : (i / 2)] = (unsigned char)(((Utils::CharToByte(v[i]) << 4) & 0xF0) | ((Utils::CharToByte(v[i + 1]) & 0x0F)));
				}

				std::ifstream file = std::ifstream(location + "kv.bin", std::ios::binary | std::ios::ate);
				int size = (int)file.tellg();
				file.seekg(0, std::ios::beg);

				if (size < 0x1EF8) {
					Log::Error(header, serverWriter, "PacketGetChallengeResponse", client.strNoKVHash + " size is below 0x1EF8");
					goto end;
				}

				std::vector<char> buffer = std::vector<char>(0x1EFF);
				if (file.read(buffer.data(), 0x1EFF)) {
					file.close();

					uint16_t kv_oddFeatures;
					memcpy(&kv_oddFeatures, buffer.data() + 0x1C, 0x2);

					fcrt = (kv_oddFeatures & 0x120) != 0;

					typeone = true;
					for (int i = 0; i < 256; ++i) {
						if ((buffer.data() + 0x1DF8)[i] != 0) {
							typeone = false;
							break;
						}
					}

					buffer.clear();
				}
			} else {
				Log::Error(header, serverWriter, "PacketGetChallengeResponse", client.strNoKVHash + "/cpukey.txt" + " can't be opened");
				goto end;
			}
		}

		/*if (client.iTimeEnd < Utils::GetTimeStamp() && client.iReserveSeconds == 0 && !bFreemode) {
			Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Client has no time left and we aren't in freemode");
			good = false;
		} else {
			for (int i = 0; i < 5; i++) {
				Socket connection("35.245.169.64", 1777);
				if (connection.InitializeConnection()) {
					Log::Success(header, serverWriter, "PacketGetChallengeResponse", "Connected to API server");
					unsigned char data[0x44];
					
					BinaryWriter writer = BinaryWriter(data, sizeof(data), LittleEndian);
					writer.WriteBytes(hvsalt, sizeof(hvsalt));
					writer.WriteBytes(sessionSalt, sizeof(sessionSalt));
					writer.WriteBytes(header->szCPU, sizeof(header->szCPU));
					writer.WriteBytes(kvcpu, sizeof(kvcpu));
					writer.WriteByte(typeone);
					writer.WriteByte(fcrt);
					writer.WriteByte(crl);
					writer.WriteByte(false);
					writer.Clean();

					if (connection.Send(data, sizeof(data))) {
						if (connection.Receive(challengeResp, sizeof(challengeResp))) {
							connection.Close();
							good = true;
							break;
						}
					}
					
					Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Failed to get a response from API server");
				} else {
					Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Failed to initialize connection to API server");
				}

				connection.Close();
			}
		}*/

		for (int i = 0; i < 5; i++) {
			// 35.245.169.64
			Socket connection("74.91.115.90", 1777);
			if (connection.InitializeConnection()) {
				Log::Success(header, serverWriter, "PacketGetChallengeResponse", "Connected to API server");
				unsigned char data[0x44];

				BinaryWriter writer = BinaryWriter(data, sizeof(data), LittleEndian);
				writer.WriteBytes(hvsalt, sizeof(hvsalt));
				writer.WriteBytes(sessionSalt, sizeof(sessionSalt));
				writer.WriteBytes(header->szCPU, sizeof(header->szCPU));
				writer.WriteBytes(kvcpu, sizeof(kvcpu));
				writer.WriteByte(typeone);
				writer.WriteByte(fcrt);
				writer.WriteByte(crl);
				writer.WriteByte(false);
				writer.Clean();

				if (connection.Send(data, sizeof(data))) {
					if (connection.Receive(challengeResp, sizeof(challengeResp))) {
						connection.Close();
						good = true;
						break;
					}
				}

				Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Failed to get a response from API server");
			} else {
				Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Failed to initialize connection to API server");
			}

			connection.Close();
		}
	} else {
		Log::Error(header, serverWriter, "PacketGetChallengeResponse", "Failed to get client data from console key");
	}

	Security::RC4(sessionSalt, sizeof(sessionSalt), challengeResp, sizeof(challengeResp));

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)(good ? RESPONSE_SUCCESS : RESPONSE_ERROR));
	writer.WriteBytes(challengeResp, sizeof(challengeResp));
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}