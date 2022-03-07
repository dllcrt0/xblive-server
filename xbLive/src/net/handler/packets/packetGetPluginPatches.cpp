#include "packetGetPluginPatches.h"

void PacketGetPluginPatches::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetPluginPatches");

	unsigned char* resp = nullptr;
	unsigned char* patchData = nullptr;
	unsigned int size = 0;
	std::string location = "";

	BinaryWriter writer;
	eResponseStatus status = RESPONSE_ERROR;

	int xexID = reader.ReadInt32();

	XexInfo xeinfo;
	if (!pMySQL.GetXexInfo(xexID, &xeinfo)) {
		Log::Error(header, serverWriter, "PacketGetPluginPatches", "Xex identifier not found: " + std::to_string(xexID));
		goto end;
	}

	location = std::string("Server Data/Plugins/") + xeinfo.strPatchName + std::string(".bin");
	if (Utils::FileExists(location.c_str())) {
		std::ifstream file(location, std::ios::binary | std::ios::ate);
		size = (int)file.tellg();
		file.seekg(0, std::ios::beg);

		if (size <= 0) {
			goto end;
		}

		std::vector<char> buffer(size);
		if (file.read(buffer.data(), size)) {
			file.close();
			patchData = (unsigned char*)Utils::Alloc(size);
			memcpy(patchData, buffer.data(), size);
			buffer.clear();
		} else {
			goto end;
		}
	}

	// "don't touch me supa secret mayo"
	static unsigned char rc4Key[] = {
		0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x74, 0x6F, 0x75, 0x63, 0x68, 0x20,
		0x6D, 0x65, 0x20, 0x73, 0x75, 0x70, 0x61, 0x20, 0x73, 0x65, 0x63, 0x72,
		0x65, 0x74, 0x20, 0x6D, 0x61, 0x79, 0x6F
	};

	Security::RC4(rc4Key, sizeof(rc4Key), patchData, size);

	status = RESPONSE_SUCCESS;
	Log::Success(header, serverWriter, "PacketGetPluginPatches", "Sending plugin patches " + xeinfo.strPatchName + ".bin with size " + std::to_string(size));

end:
	resp = (unsigned char*)Utils::Alloc(size + 8 + ENCRYPTION_STRUCT_SIZE);
	writer = BinaryWriter(resp, size + 8 + ENCRYPTION_STRUCT_SIZE);

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteInt32(size);
	if (status == RESPONSE_SUCCESS) writer.WriteBytes(patchData, size);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, size + 8 + ENCRYPTION_STRUCT_SIZE, encryption);

	free(resp);
	if (patchData) free(patchData);
}