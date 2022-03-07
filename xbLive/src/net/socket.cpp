#include "socket.h"

#define SOCKET_TIMEOUT 5000
#define min(a, b) (((a) < (b)) ? (a) : (b))

Socket Server;

Socket::Socket(uint16_t port) {
	iPort = (int)port;
}

Socket::Socket(int socket) {
	iSocket = socket;
}

Socket::Socket(const char* pHost, uint16_t port) {
	strcpy(szIP, pHost);
	iPort = (int)port;
}

void Socket::Close(std::vector<void*> thingsToDeallocate) {
	for (std::size_t i = 0; i < thingsToDeallocate.size(); i++) {
		free(thingsToDeallocate[i]);
		thingsToDeallocate.erase(thingsToDeallocate.begin() + i);
	}

	close(iSocket);
}

bool Socket::IsConnected() {
	char test = 0;

	auto ret = recv(iSocket, &test, 1, MSG_PEEK | MSG_DONTWAIT);
	if (ret == -1) {
		if (errno != EWOULDBLOCK) {
			return false;
		}
	}

	return true;
}

bool Socket::Receive(unsigned char* pBuffer, ssize_t dwSize) {
	auto startTick = Utils::GetTickCount();
	auto currentData = (char*)pBuffer;
	ssize_t dataLeft = dwSize;
	ssize_t receiveStatus = 0;

	while (dataLeft > 0) {
		if ((Utils::GetTickCount() - startTick) > SOCKET_TIMEOUT) {
			return false;
		}

		if (!IsConnected()) return false;

		auto dataChunkSize = min(2048, dataLeft);

		receiveStatus = recv(iSocket, currentData, dataChunkSize, MSG_NOSIGNAL);

		if (receiveStatus == -1 && errno != EWOULDBLOCK)
			break;

		currentData += receiveStatus;
		dataLeft -= receiveStatus;

		if (receiveStatus == 0)
			break;
	}

	if (receiveStatus == -1) {
		printf("[-] Receive failed with error %i\n", errno);
		return false;
	}

	return true;
}

bool Socket::SendErrorCode(unsigned char code) {
	unsigned char szErrorResponse[5];
	*(int*)(szErrorResponse) = 0x37133713;
	*(unsigned char*)(szErrorResponse + 4) = code;
	return Send(szErrorResponse, 5);
}

bool Socket::Send(unsigned char* pBuffer, ssize_t dwSize) {
	auto startTick = Utils::GetTickCount();
	auto currentData = (char*)pBuffer;
	ssize_t dataLeft = dwSize;
	ssize_t sendStatus = 0;

	while (dataLeft > 0) {
		if ((Utils::GetTickCount() - startTick) > SOCKET_TIMEOUT) {
			return false;
		}

		if (!IsConnected()) return false;

		auto dataChunkSize = min(2048, dataLeft);

		sendStatus = send(iSocket, currentData, dataChunkSize, MSG_NOSIGNAL);

		if (sendStatus == -1 && errno != EWOULDBLOCK)
			break;

		currentData += sendStatus;
		dataLeft -= sendStatus;
	}

	if (sendStatus == -1) {
		printf("[-] Send failed with error %i\n", errno);
		return false;
	}

	return true;
}

bool Socket::InitializeConnection() {
	struct sockaddr_in addr = { 0 };

	iSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (iSocket == -1)
		return false;

	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)iPort);
	
	struct hostent *phost = gethostbyname(szIP);
	if ((phost) && (phost->h_addrtype == AF_INET))
		addr.sin_addr = *(in_addr*)(phost->h_addr);

	if (connect(iSocket, (sockaddr*)&addr, sizeof(addr)) < 0)
		return false;

	return true;
}

bool Socket::StartListener() {
	struct sockaddr_in addr;

	iSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	int enable = 1;
	setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, &enable, 4);

	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)iPort);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(iSocket, (struct sockaddr*)&addr, sizeof(sockaddr_in))) {
		return false;
	}

	if (listen(iSocket, 5)) {
		return false;
	}

	return true;
}