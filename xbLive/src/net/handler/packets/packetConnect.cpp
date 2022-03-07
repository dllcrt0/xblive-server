#include "packetConnect.h"

void PacketConnect::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketConnect");

	unsigned char resp[1 + ENCRYPTION_STRUCT_SIZE];
	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	auto encryption = Security::CreateEncryption(&writer, header);

	writer.WriteByte(true);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}