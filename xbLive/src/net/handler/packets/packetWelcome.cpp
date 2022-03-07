#include "packetWelcome.h"

void PacketWelcome::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketWelcome");

	unsigned char resp[309 + ENCRYPTION_STRUCT_SIZE];
	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	bool hasError = false;
	char errorMsg[0x100];
	unsigned char token[0x20];

	std::string kvhashString = "00000000";
	ClientInfo client;
	XexInfo xeinfo;
	KVStats stats;
	int lastUsedVersion = 0;
	int daysOnKV = 1;
	int daysOnKVDifference = 0;
	eResponseStatus status = RESPONSE_WELCOME_NO_TIME;

	Utils::GenerateRandomBytes(token, 0x20);

	int xex = reader.ReadInt32();
	unsigned int userVersion = reader.ReadUInt32();
	unsigned int kvhash = reader.ReadUInt32();
	bool kvbanned = reader.ReadBool();

	if (kvhash != 0x0) {
		std::stringstream stream;
		stream << std::hex << kvhash;
		kvhashString = stream.str();
	}

	if (!pMySQL.GetXexInfo(xex, &xeinfo)) {
		Log::Error(header, serverWriter, "PacketWelcome", "Xex identifier not found: " + std::to_string(xex));
		status = RESPONSE_ERROR;
		hasError = true;
		snprintf(errorMsg, 0x100, "Xex identifier was invalid - please contact support and show them this message.\n\nInfo: %i", xex);
		goto end;
	}

	if (userVersion != xeinfo.dwLastVersion) {
		// needs an update
		status = RESPONSE_WELCOME_REQUIRED_UPDATE;

		pMySQL.AddRequestToken(Utils::BytesToString(token, 0x20).c_str(), Utils::BytesToString(header->szConsoleKey, 0x14).c_str());
		goto end;
	}

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client)) {
		switch (client.Status) {
		case Banned:
			status = RESPONSE_WELCOME_BANNED;
			break;
		case Disabled:
			status = RESPONSE_WELCOME_DISABLED;
			break;
		case Authed:
			status = RESPONSE_SUCCESS;
			break;
		case NoTime:
			status = RESPONSE_WELCOME_NO_TIME;
			break;
		default:
			status = RESPONSE_WELCOME_NO_TIME;
			break;
		}

		lastUsedVersion = client.iLastUsedVersion;

		// update stuff
		pMySQL.UpdateUserInfoWelcomePacket(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), kvhashString.c_str(), serverWriter.GetIP());
	} else {
		pMySQL.AddUserWelcomePacket(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), Utils::BytesToString(header->szCPU, 0x10).c_str(), serverWriter.GetIP(), kvhashString.c_str());
		status = RESPONSE_SUCCESS;
	}

	if (header->bDevkit && !client.bAllowedOnDevkit) {
		Log::Warn(header, serverWriter, "PacketWelcome", "Client is running a devkit with no access");

		status = RESPONSE_ERROR;
		hasError = true;
		snprintf(errorMsg, 0x100, "You don't have access to xbLive on devkit!");
		memset(token, 0x0, 0x20);
		goto end;
	}

	if (pMySQL.GetKVStats(kvhashString.c_str(), &stats)) {
		pMySQL.UpdateKVStat(kvhashString.c_str(), kvbanned);
	} else {
		pMySQL.AddKVStat(kvhashString.c_str(), Utils::GetTimeStamp(), Utils::GetTimeStamp(), kvbanned, kvbanned ? Utils::GetTimeStamp() : 0);
	}

	pMySQL.GetKVStats(kvhashString.c_str(), &stats);

	daysOnKVDifference = Utils::GetTimeStamp() - stats.iFirstConnection;
	if (daysOnKVDifference > 86400) {
		daysOnKV = (int)round((float)(daysOnKVDifference / 86400));
	}

	if (status == RESPONSE_WELCOME_BANNED || status == RESPONSE_WELCOME_DISABLED) {
		hasError = true;

		if (client.strNotifyOnSus.length() < 1) {
			client.strNotifyOnSus = "An unknown error occured! Rebooting...";
		}

		strcpy(errorMsg, client.strNotifyOnSus.c_str());
	} else {
		pMySQL.AddRequestToken(Utils::BytesToString(token, 0x20).c_str(), Utils::BytesToString(header->szConsoleKey, 0x14).c_str());

		if (bFreemode) {
			status = RESPONSE_WELCOME_FREEMODE;
		}
	}

	Log::Info(header, serverWriter, "PacketWelcome", "Token: " + Utils::BytesToString(token, 0x20));

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteInt32(client.iTotalChallenges);
	writer.WriteInt32(stats.iTotalChallenges); // total challenges on THIS KV
	writer.WriteInt32(lastUsedVersion);
	writer.WriteInt32(daysOnKV); // days on KV
	writer.WriteBytes(token, 0x20);
	writer.WriteByte(hasError);
	writer.WriteBytes((unsigned char*)errorMsg, 0x100);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}