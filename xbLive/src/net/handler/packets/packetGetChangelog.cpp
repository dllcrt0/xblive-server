#include "packetGetChangelog.h"

void PacketGetChangelog::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetChangelog");

	unsigned char resp[1004 + ENCRYPTION_STRUCT_SIZE];
	char message[1000];

	ClientInfo client;
	XexInfo xeinfo;
	std::string location = "";
	std::ifstream file;
	int changelogSize = 0;
	std::vector<char> buffer;
	eResponseStatus status = RESPONSE_SUCCESS;

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	int xex = reader.ReadInt32();

	if (!pMySQL.GetXexInfo(xex, &xeinfo)) {
		Log::Error(header, serverWriter, "PacketGetChangelog", "Xex identifier not found: " + std::to_string(xex));
		status = RESPONSE_ERROR;
		goto end;
	}

	location = (std::string("Server Data/Changelogs/xbLive-") + std::to_string(xeinfo.dwLastVersion) + ".txt");
	if (!Utils::FileExists(location.c_str())) {
		Log::Error(header, serverWriter, "PacketGetChangelog", location + " not found");
		status = RESPONSE_ERROR;
		goto end;
	}

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client)) {
		if (client.iLastUsedVersion != (int)xeinfo.dwLastVersion) {
			file = std::ifstream(location, std::ios::binary | std::ios::ate);
			changelogSize = (int)file.tellg();
			file.seekg(0, std::ios::beg);

			if (changelogSize <= 0) {
				Log::Error(header, serverWriter, "PacketGetChangelog", "Changelog size is below or equal to 0");
				status = RESPONSE_ERROR;
				goto end;
			}

			buffer = std::vector<char>(changelogSize);
			if (file.read(buffer.data(), changelogSize)) {
				memset(message, 0, sizeof(message));
				memcpy(message, buffer.data(), changelogSize);
				file.close();
				buffer.clear();

				pMySQL.UpdateUserLastStealthVersion(client.strConsoleKey.c_str(), (int)xeinfo.dwLastVersion);
			} else {
				Log::Error(header, serverWriter, "PacketGetChangelog", "xbLive-" + std::to_string(xeinfo.dwLastVersion) + ".txt can't be opened");
				status = RESPONSE_ERROR;
				goto end;
			}
		}
	} else {
		Log::Error(header, serverWriter, "PacketGetChangelog", "Failed to get client data");
		status = RESPONSE_ERROR;
		goto end;
	}

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteBytes((unsigned char*)message, 1000);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}