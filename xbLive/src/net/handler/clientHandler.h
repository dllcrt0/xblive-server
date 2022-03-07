#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H
#include <iostream>
#include <unordered_map>
#include "net/socket.h"
#include "net/security/security.h"
#include "database/helper/mysqlHelper.h"
#include "utils/io/binaryReader.h"
#include "utils/structs.h"

class ClientHandler {
public:
	static std::vector<std::pair<in_addr_t, SocketSpam>> SocketSpamConnectionLog;
	static bool bUsingSpamDetection;

	static void StartFreemodeWatcher();
	static void StartHeartbeatHandler();
	static void StartConnectionLogHandler();
	static void StartListener();
	static void Handler(ConnectionInfo* pClient);

	static bool IsSpammingSocket(in_addr_t ip);
};

#endif