#ifndef LOG_H
#define LOG_H
#include <string>
#include <vector>
#include <iostream>
#include "net/socket.h"
#include "structs.h"
#include "utils.h"

namespace Color {
	enum Code {
		FG_BLACK = 30,
		FG_RED = 31,
		FG_GREEN = 32,
		FG_YELLOW = 33,
		FG_BLUE = 34,
		FG_MAGENTA = 35,
		FG_CYAN = 36,
		FG_LIGHTGRAY = 37,
		FG_DEFAULT = 39,
		FG_DARKGRAY = 90,
		FG_LIGHTRED = 91,
		FG_LIGHTGREEN = 92,
		FG_LIGHTYELLOW = 93,
		FG_LIGHTBLUE = 94,
		FG_LIGHTMAGENTA = 95,
		FG_LIGHTCYAN = 96,
		FG_WHITE = 97
	};

	inline std::ostream& operator<<(std::ostream& os, Code code) {
		return os << "\033[" << static_cast<int>(code) << "m";
	}
}

class Log {
public:
	static std::string GetTimeAsString();
	static void Misc(const std::string& values);
	static void Connection(const Header* header, const Socket& client, const std::string& packetName, const std::string& values = "");
	static void Success(const Header* header, const Socket& client, const std::string& packetName, const std::string& values = "");
	static void Error(const Header* header, const Socket& client, const std::string& packetName, const std::string& values = "");
	static void Warn(const Header* header, const Socket& client, const std::string& packetName, const std::string& values = "");
	static void Info(const Header* header, const Socket& client, const std::string& packetName, const std::string& values = "");

	static void SuccessVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values);
	static void ErrorVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values);
	static void WarnVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values);
	static void InfoVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values);

	static std::string BuildVectoredString(std::vector<std::string> values);
	static void GenerateDefaultResponse(const std::string& type, const Color::Code color, const Header* header, const Socket& client, const std::string& packetName, const std::string& values = "");
private:
};

#endif