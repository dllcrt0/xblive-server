#include "packetDownloadPlugin.h"

void PacketDownloadPlugin::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketDownloadPlugin");

	unsigned char* resp = nullptr;
	unsigned char* xexBytes = nullptr;

	int xexSize = 0;
	int len = 0;
	std::string location = "";
	XexInfo xeinfo;
	ClientInfo info;
	eResponseStatus status = RESPONSE_SUCCESS;

	bool sizeOnly = reader.ReadBool();
	int pluginID = reader.ReadInt32();

	BinaryWriter writer;

	if (!pMySQL.GetXexInfo(pluginID, &xeinfo)) {
		Log::Error(header, serverWriter, "PacketDownloadPlugin", "Xex identifier not found: " + std::to_string(pluginID));
		status = RESPONSE_ERROR;
		goto end;
	}

	if (!xeinfo.bEnabled) {
		Log::Error(header, serverWriter, "PacketDownloadPlugin", "Xex isn't enabled: " + std::to_string(pluginID));
		status = RESPONSE_ERROR;
		goto end;
	}

	pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &info);

	if (header->bDevkit && xeinfo.dwTitle != 0) {
		if (!info.bDevkitCheats) {
			Log::Error(header, serverWriter, "PacketDownloadPlugin", "Client is running devkit and doesn't have devkit cheats");
			status = RESPONSE_ERROR;
			goto end;
		}
	}

	if (xeinfo.bBetaOnly) {
		if (!info.bBetaAccess) {
			Log::Error(header, serverWriter, "PacketDownloadPlugin", "Client doesn't have beta access");
			status = RESPONSE_ERROR;
			goto end;
		}
	}

	if (info.iTimeEnd < Utils::GetTimeStamp() && info.iReserveSeconds == 0 && !bFreemode) {
		Log::Error(header, serverWriter, "PacketDownloadPlugin", "Client doesn't have any time");
		status = RESPONSE_ERROR;
		goto end;
	}

	location = (std::string("Server Data/Plugins/") + xeinfo.strName);
	if (Utils::FileExists(location.c_str())) {
		std::ifstream file(location, std::ios::binary | std::ios::ate);
		xexSize = (int)file.tellg();
		file.seekg(0, std::ios::beg);

		if (xexSize <= 0) {
			Log::Error(header, serverWriter, "PacketDownloadPlugin", "File had a size of 0");
			status = RESPONSE_ERROR;
		}

		std::vector<char> buffer(xexSize);
		if (file.read(buffer.data(), xexSize)) {
			xexBytes = (unsigned char*)Utils::Alloc(xexSize);
			memcpy(xexBytes, buffer.data(), xexSize);
			buffer.clear();
		}

		file.close();
	} else {
		Log::Error(header, serverWriter, "PacketDownloadPlugin", "File wasn't found on server");
		status = RESPONSE_ERROR;
	}

end:
	len = 4 + (sizeOnly ? 4 : xexSize) + ENCRYPTION_STRUCT_SIZE;
	resp = (unsigned char*)Utils::Alloc(len);
	writer = BinaryWriter(resp, len);

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);

	if (status == RESPONSE_SUCCESS) {
		if (sizeOnly) {
			writer.WriteInt32(xexSize);
			Log::Success(header, serverWriter, "PacketDownloadPlugin", "Sent xex size to client: " + std::to_string(xexSize));
		} else {
			writer.WriteBytes(xexBytes, xexSize);
			Log::Success(header, serverWriter, "PacketDownloadPlugin", "Streamed " + std::to_string(xexSize) + " bytes to client");
		}
	} else {
		writer.WriteInt32(RESPONSE_ERROR);
	}

	writer.Clean();

	Security::SendPacket(serverWriter, resp, len, encryption);
	
	free(resp);
	if (xexBytes) free(xexBytes);
}