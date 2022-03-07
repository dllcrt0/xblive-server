#include "packetGetPlugins.h"

void PacketGetPlugins::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetPlugins");

	std::vector<XexInfo> xexInfos = pMySQL.GetXexInfos();

	unsigned char resp[0x205 + ENCRYPTION_STRUCT_SIZE];
	unsigned char data[0x200];
	eResponseStatus status = RESPONSE_ERROR;

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));
	BinaryWriter dataWriter = BinaryWriter(data, sizeof(data));

	int realCount = 0;

	ClientInfo info;
	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &info)) {
		status = RESPONSE_SUCCESS;

		for (std::size_t i = 0; i < xexInfos.size(); i++) {
			if (xexInfos[i].dwTitle != 0x0) {
				if (xexInfos[i].bBetaOnly && !info.bBetaAccess) continue;
				realCount++;
			}
		}

		dataWriter.WriteInt32(realCount);

		for (std::size_t i = 0; i < xexInfos.size(); i++) {
			auto xex = xexInfos[i];
			if (xexInfos[i].dwTitle != 0x0) {
				dataWriter.WriteInt32(xex.iID);
				dataWriter.WriteUInt32(xex.dwLastVersion);
				dataWriter.WriteUInt32(xex.dwTitle);
				dataWriter.WriteUInt32(xex.dwTitleTimestamp);

				if (xex.bBetaOnly && !info.bBetaAccess)
					dataWriter.WriteByte(false);
				else dataWriter.WriteByte(xex.bEnabled);

				auto bytes = Utils::StringToBytes(xex.strEncryptionKey);
				dataWriter.WriteBytes((unsigned char*)bytes.data(), (int)bytes.size());
			}
		}

		dataWriter.Clean();

		Log::Success(header, serverWriter, "PacketGetPlugins", "Sending " + std::to_string(realCount) + " plugins to client");
	}

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteByte(realCount >= 1);
	writer.WriteBytes(data, sizeof(data));
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}