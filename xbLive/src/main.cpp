#include <cstdlib>
#include <ctime>
#include "net/socket.h"
#include "net/handler/clientHandler.h"

// #define LOCAL_LISTENER

int main() {
	// seed rand with current time
	srand((unsigned int)std::time(nullptr));

	// initialize the server instance with the port we're using (todo: get from ini)
	Server = Socket((uint16_t)17544);

	// create the thread that handles incoming connections
	Utils::CreateThread((void*)ClientHandler::StartListener, nullptr);

#ifndef LOCAL_LISTENER
	// create the thread that checks every minute to see if freemode is enabled
	Utils::CreateThread((void*)ClientHandler::StartFreemodeWatcher, nullptr);

	// create the thread that handles removing outdated access tokens
	Utils::CreateThread((void*)ClientHandler::StartHeartbeatHandler, nullptr);
#endif

	// create the thread that handles removing potential spam logs
	Utils::CreateThread((void*)ClientHandler::StartConnectionLogHandler, nullptr);

	// infinite loop to make sure the program continues to run
	while (true) {
		sleep(10);
	}

    return 0;
}