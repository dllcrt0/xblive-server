#ifndef PACKET_HEARTBEAT_H
#define PACKET_HEARTBEAT_H
#include <iostream>
#include <fstream>
#include "net/socket.h"
#include "net/security/security.h"
#include "utils/io/binaryReader.h"
#include "utils/structs.h"
#include "database/helper/mysqlHelper.h"
#include "utils/log.h"

class PacketHeartbeat {
public:
	static void Handle(BinaryReader reader, Socket serverWriter, Header* header);
};

#endif