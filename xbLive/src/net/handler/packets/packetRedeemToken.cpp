#include "packetRedeemToken.h"

void PacketRedeemToken::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketRedeemToken");

	unsigned char resp[9 + ENCRYPTION_STRUCT_SIZE];
	eResponseStatus status = RESPONSE_ERROR;

	bool validToken = false;
	bool alreadyRedeemed = false;
	int secondsAdded = 0;

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	char* token = reader.ReadChars(12);

	if (strlen(token) < 1) {
		goto end;
	}

	if (strlen(token) > 12) {
		token[12] = '\0';
	}

	validToken = pMySQL.DoesRedeemTokenExist(token, &alreadyRedeemed);

	if (validToken) {
		if (!alreadyRedeemed) {
			pMySQL.GetTokenTimeAndRedeem(token, Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), &secondsAdded);
			Log::Success(header, serverWriter, "PacketRedeemToken", "Token: " + std::string(token) + " redeemed, added " + (secondsAdded == INT_MAX ? "lifetime " : std::to_string(secondsAdded) + " seconds ") + "to users account");
		} else {
			Log::Warn(header, serverWriter, "PacketRedeemToken", "Token: " + std::string(token) + " already redeemed");
		}
	} else {
		Log::Warn(header, serverWriter, "PacketRedeemToken", "Token: " + std::string(token) + " not valid");
	}

	status = RESPONSE_SUCCESS;

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteByte(validToken && !alreadyRedeemed);
	writer.WriteInt32(secondsAdded);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}