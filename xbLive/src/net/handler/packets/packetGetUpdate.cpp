#include "packetGetUpdate.h"

void PacketGetUpdate::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetUpdate");

	unsigned char* resp = nullptr;
	unsigned char* xexBytes = nullptr;
	int xexSize = 0;
	int len = 0;
	eResponseStatus status = RESPONSE_SUCCESS;

	bool sizeOnly = reader.ReadBool();

	BinaryWriter writer;

	if (Utils::FileExists("Server Data/Plugins/xbLive.xex")) {
		std::ifstream file("Server Data/Plugins/xbLive.xex", std::ios::binary | std::ios::ate);
		xexSize = (int)file.tellg();

		if (!sizeOnly) {
			file.seekg(0, std::ios::beg);

			if (xexSize <= 0) {
				Log::Error(header, serverWriter, "PacketGetUpdate", "File has size of 0");
				status = RESPONSE_ERROR;
				goto end;
			}

			std::vector<char> buffer(xexSize);
			if (file.read(buffer.data(), xexSize)) {
				xexBytes = (unsigned char*)Utils::Alloc(xexSize);
				memcpy(xexBytes, buffer.data(), xexSize);
				file.close();
				buffer.clear();
			}
		}
	} else {
		Log::Error(header, serverWriter, "PacketGetUpdate", "File wasn't found on server");
		status = RESPONSE_ERROR;
		goto end;
	}

end:
	len = 4 + (status == RESPONSE_ERROR ? 0 : (sizeOnly ? 4 : xexSize)) + ENCRYPTION_STRUCT_SIZE;
	resp = (unsigned char*)Utils::Alloc(len);
	writer = BinaryWriter(resp, len);

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);

	if (status == RESPONSE_SUCCESS) {
		if (sizeOnly) {
			writer.WriteInt32(xexSize);
			Log::Success(header, serverWriter, "PacketGetUpdate", "Sent xex size to client: " + std::to_string(xexSize));
		} else {
			writer.WriteBytes(xexBytes, xexSize);
			Log::Success(header, serverWriter, "PacketGetUpdate", "Streamed " + std::to_string(xexSize) + " bytes to client");
		}
	}

	writer.Clean();

	Security::SendPacket(serverWriter, resp, len, encryption);

	free(resp);
	if (xexBytes) free(xexBytes);
}