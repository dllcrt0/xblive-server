#include "packetGetTime.h"

void PacketGetTime::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetTime");

	unsigned char resp[26 + ENCRYPTION_STRUCT_SIZE];

	ClientInfo client;
	bool hasLifetime = false;
	int days = 0, hours = 0, minutes = 0, seconds = 0;
	int secondsLeft = 0;
	bool hasReserve = false;
	eResponseStatus status = RESPONSE_SUCCESS;

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	if (pMySQL.GetClientData(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &client)) {
		hasReserve = client.iReserveSeconds >= 300;

		if (hasReserve) {
			secondsLeft = client.iReserveSeconds;
			if (client.iReserveSeconds == 0x7FFFFFFF) {
				Log::Info(header, serverWriter, "PacketGetTime", "Reserve lifetime");
			} else {
				TimeCalc reserveTime(client.iReserveSeconds);
				days = reserveTime.iDays;
				hours = reserveTime.iHours;
				minutes = reserveTime.iMinutes;
				seconds = reserveTime.iSeconds;

				Log::Info(header, serverWriter, "PacketGetTime", std::to_string(days) + "D " + std::to_string(hours) + "H " + std::to_string(minutes) + "M " + std::to_string(seconds) + "S (R)");
			}
		} else {
			if (client.iTimeEnd == 0x7FFFFFFF) {
				hasLifetime = true;
				Log::Info(header, serverWriter, "PacketGetTime", "Lifetime");
			} else {
				if (client.iTimeEnd > Utils::GetTimeStamp())
					secondsLeft = client.iTimeEnd - Utils::GetTimeStamp();

				TimeCalc time(secondsLeft);
				days = time.iDays;
				hours = time.iHours;
				minutes = time.iMinutes;
				seconds = time.iSeconds;

				Log::Info(header, serverWriter, "PacketGetTime", std::to_string(days) + "D " + std::to_string(hours) + "H " + std::to_string(minutes) + "M " + std::to_string(seconds) + "S");
			}
		}
	} else {
		Log::Error(header, serverWriter, "PacketGetTime", "Failed to find user data");
		status = RESPONSE_ERROR;
	}

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteByte(hasReserve);
	writer.WriteByte(hasLifetime);
	writer.WriteInt32(days);
	writer.WriteInt32(hours);
	writer.WriteInt32(minutes);
	writer.WriteInt32(seconds);
	writer.WriteInt32(secondsLeft);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}