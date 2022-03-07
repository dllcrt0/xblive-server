#ifndef UTILS_H
#define UTILS_H
#include <string>
#include <string.h>
#include <vector>
#include <sys/time.h>
#include <sys/stat.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <limits.h>
#include <iostream>
#include <dirent.h>

extern bool bFreemode;

class Utils {
public:
	static unsigned char CharToByte(char input);
	static void CreateThread(void* pThread, void* pParam);
	static void GenerateRandomBytes(unsigned char* arr, int len);
	static std::string BytesToString(const unsigned char *data, size_t len);
	static std::vector<char> StringToBytes(std::string hex);
	static std::vector<unsigned char> IntToBytes(int paramInt);
	static bool FileExists(const char* file);
	static bool DirectoryExists(const char* pzPath);
	static std::string GetCurrentPath();
	static void* Alloc(int size);
	static unsigned int GetTickCount();
	static int GetTimeStamp();
	static void BanClient(std::string ip);
	static void UnbanClient(std::string ip);
	static std::vector<std::string> GetFilesInDirectory(std::string directDirectory);

	template<typename T>
	static void GetBytes(unsigned char* byteK, T k, int noOfBytes) {
		for (int i = 0; i < noOfBytes; i++) {
			byteK[i] = (unsigned char)((k >> (8 * i)) & 0xFF);
		}
	}
};

#endif