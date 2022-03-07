#ifndef PACKET_WELCOME_H
#define PACKET_WELCOME_H
#include <iostream>
#include "net/socket.h"
#include "net/security/security.h"
#include "utils/io/binaryReader.h"
#include "utils/structs.h"
#include "database/helper/mysqlHelper.h"
#include "utils/log.h"

class PacketWelcome {
public:
	static void Handle(BinaryReader reader, Socket serverWriter, Header* header);
};

#endif