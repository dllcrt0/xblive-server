#include "packetHeartbeat.h"

void PacketHeartbeat::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketHeartbeat");

	unsigned char resp[39 + ENCRYPTION_STRUCT_SIZE];

	std::vector<std::string> vectorPrint;

	bool hasLifetime = false;
	int days = 0, hours = 0, minutes = 0, seconds = 0;
	int secondsLeft = 0;
	bool hasReserve = false;
	bool hasVerificationWaiting = false;
	char verificationKey[10];
	std::string currentTitleString = "00000000";
	std::string kvhashString = "00000000";

	ConsoleVerification verification;
	ClientInfo client;
	XexInfo xeinfo;
	eResponseStatus status = RESPONSE_SUCCESS;

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	pMySQL.UpdateRequestTokenHeartbeat(Utils::BytesToString(header->szToken, 0x20).c_str());

	int xex = reader.ReadInt32();
	unsigned int currentTitle = reader.ReadUInt32();
	unsigned int kvhash = reader.ReadUInt32();
	bool kvbanned = reader.ReadBool();
	char* gamertag = reader.ReadChars(16);

	if (strlen(gamertag) > 16) {
		gamertag[16] = '\0';
	}

	if (strcmp(gamertag, "----------------")) {
		vectorPrint.push_back(gamertag);
	}

	if (kvhash != 0x0) {
		std::stringstream stream;
		stream << std::hex << kvhash;
		kvhashString = stream.str();
	}

	if (currentTitle != 0x0) {
		std::stringstream stream2;
		stream2 << std::hex << currentTitle;
		currentTitleString = stream2.str();
	}

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client)) {
		if (client.iTimeEnd > Utils::GetTimeStamp()) {
			secondsLeft = client.iTimeEnd - Utils::GetTimeStamp();
		}

		TimeCalc time(secondsLeft);
		days = time.iDays;
		hours = time.iHours;
		minutes = time.iMinutes;
		seconds = time.iSeconds;

		pMySQL.UpdateUserGamertag(client, gamertag);

		switch (client.Status) {
			case Banned:
			case Disabled:
				status = RESPONSE_ERROR;
				goto end;
			default: break;
		}

		if (client.iReserveSeconds >= 300) {
			if (client.iReserveSeconds != 0x7FFFFFFF) {
				if (client.iReserveSeconds >= 300) {
					client.iReserveSeconds -= 300;
				} else {
					client.iReserveSeconds = 0;
				}

				pMySQL.UpdateUserReserveTime(client, client.iReserveSeconds);
				pMySQL.RefreshTimeInfo(client.strConsoleKey.c_str());
			}

			secondsLeft = client.iReserveSeconds;
			hasReserve = client.iReserveSeconds >= 300;

			if (client.iReserveSeconds == 0x7FFFFFFF) {
				vectorPrint.push_back("Lifetime (R)");
			} else {
				TimeCalc reserveTime(client.iReserveSeconds);
				days = reserveTime.iDays;
				hours = reserveTime.iHours;
				minutes = reserveTime.iMinutes;
				seconds = reserveTime.iSeconds;

				vectorPrint.push_back(std::to_string(days) + "D " + std::to_string(hours) + "H " + std::to_string(minutes) + "M " + std::to_string(seconds) + "S (R)");
			}

			pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client);

			if (client.iTimeEnd > Utils::GetTimeStamp()) {
				secondsLeft = client.iTimeEnd - Utils::GetTimeStamp();
			}
		} else {
			TimeCalc timeLeft(secondsLeft);
			days = timeLeft.iDays;
			hours = timeLeft.iHours;
			minutes = timeLeft.iMinutes;
			seconds = timeLeft.iSeconds;

			if (client.iTimeEnd == 0x7FFFFFFF) {
				hasLifetime = true;
				vectorPrint.push_back("Lifetime");
			} else {
				vectorPrint.push_back(std::to_string(days) + "D " + std::to_string(hours) + "H " + std::to_string(minutes) + "M " + std::to_string(seconds) + "S");
			}
		}
	} else {
		Log::Error(header, serverWriter, "PacketHeartbeat", "Failed to resolve client info");
		status = RESPONSE_ERROR;
		goto end;
	}

	if (!pMySQL.GetXexInfo(xex, &xeinfo)) {
		Log::Error(header, serverWriter, "PacketHeartbeat", "Xex identifier not found: " + std::to_string(xex));
		status = RESPONSE_ERROR;
		goto end;
	}

	if (pMySQL.GetConsoleVerification(Utils::BytesToString(header->szCPU, 0x10).c_str(), &verification)) {
		if (Utils::GetTimeStamp() - verification.iTimeRequested > 3600) {
			// been an hour or more, delete the verification.
			pMySQL.DeleteConsoleVerification(Utils::BytesToString(header->szCPU, 0x10).c_str());
		} else {
			Log::Info(header, serverWriter, "PacketHeartbeat", "Active verification request: " + verification.strVerificationKey);
			hasVerificationWaiting = true;
			strcpy(verificationKey, verification.strVerificationKey.c_str());
		}
	}

	pMySQL.UpdateKVStat(kvhashString.c_str(), kvbanned);

	vectorPrint.push_back(currentTitleString);
	vectorPrint.push_back(kvhashString);
	vectorPrint.push_back(kvbanned ? "Banned" : "Unbanned");

	pMySQL.UpdateTokenActiveTitle(Utils::BytesToString(header->szToken, 0x20).c_str(), currentTitleString.c_str());

	Log::InfoVector(header, serverWriter, "PacketHeartbeat", vectorPrint);

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteByte(bFreemode);
	writer.WriteByte(hasReserve);
	writer.WriteByte(hasLifetime);
	writer.WriteInt32(days);
	writer.WriteInt32(hours);
	writer.WriteInt32(minutes);
	writer.WriteInt32(seconds);
	writer.WriteInt32(secondsLeft);
	writer.WriteByte(client.bConsoleLinked);
	writer.WriteByte(hasVerificationWaiting);
	writer.WriteBytes((unsigned char*)verificationKey, 10);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}