#include "packetGetTitlePatches.h"

void PacketGetTitlePatches::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetTitlePatches");

	unsigned char* resp = nullptr;
	unsigned char* patchData = nullptr;
	int size = 0;

	BinaryWriter writer;
	eResponseStatus status = RESPONSE_ERROR;

	unsigned int title = reader.ReadUInt32();
	unsigned int stamp = reader.ReadUInt32();

	std::stringstream stream;
	stream << std::hex << title;
	std::string titleString = stream.str();
	std::transform(titleString.begin(), titleString.end(), titleString.begin(), ::toupper);

	std::stringstream stream2;
	stream2 << std::hex << stamp;
	std::string stampString = stream2.str();
	std::transform(stampString.begin(), stampString.end(), stampString.begin(), ::toupper);

	Log::Info(header, serverWriter, "PacketGetTitlePatches", "Checking for patches for " + titleString + "-" + stampString);

	std::string location = std::string("Server Data/Patches/") + titleString + std::string("-") + stampString + std::string(".bin");
	if (title == 0 || stamp == 0 || !Utils::FileExists(location.c_str())) {
		goto end;
	}

	if (Utils::FileExists(location.c_str())) {
		std::ifstream file(location, std::ios::binary | std::ios::ate);
		size = (int)file.tellg();
		file.seekg(0, std::ios::beg);

		if (size <= 0) {
			Log::Error(header, serverWriter, "PacketGetTitlePatches", "Size is below or equal to 0");
			goto end;
		}

		std::vector<char> buffer(size);
		if (file.read(buffer.data(), size)) {
			patchData = (unsigned char*)Utils::Alloc(size);
			memcpy(patchData, buffer.data(), size);
			file.close();
			buffer.clear();
		} else {
			Log::Error(header, serverWriter, "PacketGetTitlePatches", "Couldn't read file");
			goto end;
		}
	}

	static unsigned char rc4Key[] = {
		0x73, 0x75, 0x70, 0x65, 0x72, 0x20, 0x63, 0x6F, 0x6F, 0x6C, 0x20, 0x72,
		0x63, 0x34, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x64, 0x61, 0x64, 0x64, 0x79,
		0x20, 0x75, 0x77, 0x75
	};

	Security::RC4(rc4Key, sizeof(rc4Key), patchData, size);
	status = RESPONSE_SUCCESS;
	Log::Success(header, serverWriter, "PacketGetTitlePatches", "Sending patches with size " + std::to_string(size));

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