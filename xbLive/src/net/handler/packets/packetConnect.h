#ifndef PACKET_CONNECT_H
#define PACKET_CONNECT_H
#include <iostream>
#include "net/socket.h"
#include "net/security/security.h"
#include "utils/io/binaryReader.h"
#include "utils/structs.h"
#include "utils/log.h"

class PacketConnect {
public:
	static void Handle(BinaryReader reader, Socket serverWriter, Header* header);
};

#endif