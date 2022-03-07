#ifndef PACKET_XOSC_H
#define PACKET_XOSC_H
#include <iostream>
#include <fstream>
#include "net/socket.h"
#include "net/security/security.h"
#include "utils/io/binaryReader.h"
#include "utils/structs.h"
#include "database/helper/mysqlHelper.h"
#include "utils/log.h"
#include "net/crypto/sha1.h"

class PacketXOSC {
public:
	static void Handle(BinaryReader reader, Socket serverWriter, Header* header);
};

#endif