#ifndef PACKET_BO3_H
#define PACKET_BO3_H
#include <iostream>
#include <fstream>
#include "net/socket.h"
#include "net/security/security.h"
#include "utils/io/binaryReader.h"
#include "utils/structs.h"
#include "database/helper/mysqlHelper.h"
#include "utils/log.h"

class PacketBO3 {
public:
	static void Handle(BinaryReader reader, Socket serverWriter, Header* header);
};

#endif