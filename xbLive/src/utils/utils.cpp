#include "utils.h"

bool bFreemode;

void Utils::CreateThread(void* pThread, void* pParam) {
	pthread_t pThreadHandle;
	pthread_create(&pThreadHandle, 0, (void*(*)(void*))pThread, pParam);
	pthread_detach(pThreadHandle);
}

unsigned char Utils::CharToByte(char input) {
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
}

unsigned int Utils::GetTickCount() {
	struct timeval tv;
	if (gettimeofday(&tv, 0) != 0) {
		return 0;
	}

	return ((unsigned int)tv.tv_sec * 1000) + ((unsigned int)tv.tv_usec / 1000);
}

void* Utils::Alloc(int size) {
	auto allocated = malloc(size);
	memset(allocated, 0, size);
	return allocated;
}

int Utils::GetTimeStamp() {
	return (int)std::time(0);
}

void Utils::BanClient(std::string ip) {
	std::stringstream stream;
	stream << "/sbin/iptables -A INPUT -s " << ip << " -p tcp -m tcp --dport 17544 -j DROP";
	system(stream.str().c_str());
	std::cout << "[!] Banned IP " << ip << " from the firewall!" << std::endl;
}

void Utils::UnbanClient(std::string ip) {
	std::stringstream stream;
	stream << "/sbin/iptables -D INPUT -s " << ip << " -p tcp -m tcp --dport 17544 -j DROP";
	system(stream.str().c_str());
}

std::string Utils::BytesToString(const unsigned char *data, size_t len) {
	std::stringstream str;
	str.setf(std::ios_base::hex, std::ios::basefield);
	str.setf(std::ios_base::uppercase);
	str.fill('0');

	for (size_t i = 0; i < len; ++i) {
		str << std::setw(2) << (unsigned short)data[i];
	}

	return str.str();
}

std::vector<char> Utils::StringToBytes(std::string hex) {
	std::vector<char> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

std::vector<unsigned char> Utils::IntToBytes(int paramInt) {
	std::vector<unsigned char> arrayOfByte(4);
	for (int i = 0; i < 4; i++)
		arrayOfByte[3 - i] = (unsigned char)(paramInt >> (i * 8));
	return arrayOfByte;
}

void Utils::GenerateRandomBytes(unsigned char* arr, int len) {
	for (int i = 0; i < len; i++) {
		arr[i] = (unsigned char)(rand() % 256);
	}
}

bool Utils::FileExists(const char* file) {
	struct stat buffer;
	return (stat(file, &buffer) == 0);
}

bool Utils::DirectoryExists(const char* pzPath) {
	if (pzPath == NULL) return false;

	DIR* pDir;
	bool bExists = false;

	pDir = opendir(pzPath);

	if (pDir != NULL) {
		bExists = true;
		closedir(pDir);
	}

	return bExists;
}

std::string Utils::GetCurrentPath() {
	char result[256];
	ssize_t count = readlink("/proc/self/exe", result, 256);
	auto s = std::string(result, (count > 0) ? count : 0);
	return s.substr(0, s.size() - 11);
}

std::vector<std::string> Utils::GetFilesInDirectory(std::string directDirectory) {
	std::vector<std::string> files;

	DIR* dir;
	dirent* ent;

	if ((dir = opendir(directDirectory.c_str())) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_name) {
				if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
					files.push_back(ent->d_name);
				}
			}
		}

		closedir(dir);
	}

	return files;
}