#include "log.h"

std::string Log::GetTimeAsString() {
	tm timeStruct;
	time_t currentTime = std::time(nullptr);
	localtime_r(&currentTime, &timeStruct);

	static char buffer[100];
	sprintf(buffer, "[%i-%i-%i %02d:%02d:%02d]", timeStruct.tm_mday, timeStruct.tm_mon + 1, timeStruct.tm_year + 1900, timeStruct.tm_hour, timeStruct.tm_min, timeStruct.tm_sec);
	return buffer;
}

std::string GetPadding(std::string ip) {
	std::string str = "";
	
	int length = (15 - (int)ip.length());
	for (int i = 0; i < length; i++) {
		str += " ";
	}

	return str;
}

void Log::GenerateDefaultResponse(const std::string& type, const Color::Code color, const Header* header, const Socket& client, const std::string& packetName, const std::string& values) {
	std::cout << Color::FG_LIGHTGRAY << GetTimeAsString() << " " << Color::FG_DEFAULT
		<< Color::FG_LIGHTMAGENTA << Utils::BytesToString(header->szCPU, 0x10) << Color::FG_DEFAULT 
		<< " [" << Color::FG_CYAN << client.GetIP() << Color::FG_DEFAULT << "] " << color
		<< GetPadding(client.GetIP()) << type << Color::FG_DEFAULT << " [" << packetName << "]";

	if (values != "") {
		std::cout << " " << values;
	}

	std::cout << std::endl;
}

void Log::Misc(const std::string& values) {
	std::cout << Color::FG_LIGHTGRAY << GetTimeAsString() << " " << Color::FG_DEFAULT << values << std::endl;
}

void Log::Connection(const Header* header, const Socket& client, const std::string& packetName, const std::string& values) {
	GenerateDefaultResponse("Connection", Color::FG_BLUE, header, client, packetName, values);
}

void Log::Success(const Header* header, const Socket& client, const std::string& packetName, const std::string& values) {
	GenerateDefaultResponse("Success   ", Color::FG_GREEN, header, client, packetName, values);
}

void Log::Error(const Header* header, const Socket& client, const std::string& packetName, const std::string& values) {
	GenerateDefaultResponse("Error     ", Color::FG_RED, header, client, packetName, values);
}

void Log::Warn(const Header* header, const Socket& client, const std::string& packetName, const std::string& values) {
	GenerateDefaultResponse("Warn      ", Color::FG_YELLOW, header, client, packetName, values);
}

void Log::Info(const Header* header, const Socket& client, const std::string& packetName, const std::string& values) {
	GenerateDefaultResponse("Info      ", Color::FG_MAGENTA, header, client, packetName, values);
}

std::string Log::BuildVectoredString(std::vector<std::string> values) {
	std::string value = "";

	if (values.size() > 0) {
		value = "(";
		for (std::size_t i = 0; i < values.size(); i++) {
			if (values[i] == "") {
				values.erase(values.begin() + i);
			}
		}

		for (std::size_t i = 0; i < values.size(); i++) {
			if (i == values.size() - 1) {
				// last
				value += values[i];
			} else {
				value += (values[i] + ", ");
			}
		}

		value += ")";
	}

	return value;
}

void Log::SuccessVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values) {
	GenerateDefaultResponse("Success   ", Color::FG_GREEN, header, client, packetName, BuildVectoredString(values));
}

void Log::ErrorVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values) {
	GenerateDefaultResponse("Error     ", Color::FG_RED, header, client, packetName, BuildVectoredString(values));
}

void Log::WarnVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values) {
	GenerateDefaultResponse("Warn      ", Color::FG_YELLOW, header, client, packetName, BuildVectoredString(values));
}

void Log::InfoVector(const Header* header, const Socket& client, const std::string& packetName, const std::vector<std::string>& values) {
	GenerateDefaultResponse("Info      ", Color::FG_MAGENTA, header, client, packetName, BuildVectoredString(values));
}