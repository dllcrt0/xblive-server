#ifndef SOCKET_H
#define SOCKET_H
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include "utils/utils.h"

class Socket {
public:
	Socket() {};
	Socket(uint16_t port);
	Socket(int socket);
	Socket(const char* pHost, uint16_t port); // not needed

	void Close(std::vector<void*> thingsToDeallocate = std::vector<void*>());
	bool IsConnected();

	bool SendErrorCode(unsigned char code);
	bool Receive(unsigned char* pBuffer, ssize_t dwSize);
	bool Send(unsigned char* pBuffer, ssize_t dwSize);

	bool InitializeConnection();
	bool StartListener();

	void SetIP(const char* ip) { strcpy(szIP, ip); }
	int GetSocket() { return iSocket; }
	const char* GetIP() const { return szIP; }
private:
	int iSocket;
	int iPort;
	char szIP[16];
};

extern Socket Server;

#endif