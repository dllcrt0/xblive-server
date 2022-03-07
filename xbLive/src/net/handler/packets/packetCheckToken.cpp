#include "packetCheckToken.h"

void PacketCheckToken::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketCheckToken");

	unsigned char resp[6 + ENCRYPTION_STRUCT_SIZE];

	eResponseStatus status = RESPONSE_ERROR;
	bool validToken = false;
	bool alreadyRedeemed = false;

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
		Log::Success(header, serverWriter, "PacketCheckToken", "Token: " + std::string(token) + (alreadyRedeemed ? " already redeemed" : " not redeemed"));
	} else {
		Log::Warn(header, serverWriter, "PacketCheckToken", "Token: " + std::string(token) + " not valid");
	}

	status = RESPONSE_SUCCESS;

end:
	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteInt32((int)status);
	writer.WriteByte(validToken);
	writer.WriteByte(alreadyRedeemed);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}