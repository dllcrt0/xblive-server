#include "packetGetKVStats.h"

void PacketGetKVStats::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketGetKVStats");
	
	unsigned char resp[29 + ENCRYPTION_STRUCT_SIZE];
	eResponseStatus status = RESPONSE_ERROR;
	KVStats info;
	TimeCalc calculated(0);

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	unsigned int kvhash = reader.ReadUInt32();
	
	std::string kvhashString = "00000000";

	if (kvhash != 0x0) {
		std::stringstream stream;
		stream << std::hex << kvhash;
		kvhashString = stream.str();
	}

	if (pMySQL.GetKVStats(kvhashString.c_str(), &info)) {
		status = RESPONSE_SUCCESS;
		int toCalc = Utils::GetTimeStamp() - ((info.bBanned && info.iBannedTime != 0) ? info.iBannedTime : info.iFirstConnection);
		calculated = TimeCalc(toCalc);

		Log::Info(header, serverWriter, "PacketGetKVStats", std::to_string(calculated.iDays) + "D " + std::to_string(calculated.iHours) + "H " + std::to_string(calculated.iMinutes) + "M " + std::to_string(calculated.iSeconds) + "S");
	}

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteInt32(calculated.iYears);
	writer.WriteInt32(calculated.iDays);
	writer.WriteInt32(calculated.iHours);
	writer.WriteInt32(calculated.iMinutes);
	writer.WriteInt32(calculated.iSeconds);
	writer.WriteByte(info.bBanned);
	writer.WriteInt32(info.iTotalChallenges);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}