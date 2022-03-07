#ifndef MYSQL_HELPER_H
#define MYSQL_HELPER_H
#include <vector>
#include <cstring>
#include "database/mysql.h"
#include "utils/json.h"
#include "utils/structs.h"
#include "utils/utils.h"

class MySQL {
public:
	bool IsFreemode();
	std::vector<XexInfo> GetXexInfos();
	bool GetXexInfo(int id, XexInfo* ptr);
	bool DoesRedeemTokenExist(char* token, bool* alreadyRedeemed);
	std::vector<RedeemTokens> GetRedeemTokens();
	std::vector<ClientEndPoint> GetAllClientEndPoints();
	bool GetClientEndPoint(const char* token, ClientEndPoint* ptr);
	void DeleteConsoleVerification(const char* cpuKey);
	bool GetConsoleVerification(const char* cpuKey, ConsoleVerification* ptr);
	bool GetClientData(const char* consoleKey, ClientInfo* ptr);
	bool GetClientDataFromID(int id, ClientInfo* ptr);
	std::vector<KVs> GetKVs();
	bool GetKVStats(const char* kvHash, KVStats* ptr);
	void UpdateKVStat(const char* kvHash, bool banned);
	void AddKVStat(const char* kvHash, int firstConnection, int lastConnection, bool banned, int bannedTime);
	void RemoveRequestToken(const char* token);
	bool DoesRequestTokenExist(const char* token, const char* consoleKey);
	void AddRequestToken(const char* token, const char* consoleKey);
	void UpdateRequestTokenHeartbeat(const char* token);
	void UpdateUsingKVEndpointStatus(const char* token, bool status);
	void UpdateClientNoKVHash(const char* consoleKey, std::string hash);
	void UpdateClientNoKVLastRefresh(const char* consoleKey);
	void IncrementKVUsesCount(std::string hash);
	void DecrementKVUsesCount(std::string hash);
	void IncrementRequestTokenChallengeCount(const char* token);
	void IncrementRequestTokenConnectionCount(const char* token);
	int GetRequestTokenConnectionCount(const char* token);
	void BanClient(const char* consoleKey, const char* reason);
	void UpdateUserInfoWelcomePacket(const char* consoleKey, const char* kvhash, const char* ip);
	void UpdateTokenActiveTitle(const char* token, const char* title);
	void AddUserWelcomePacket(const char* consoleKey, const char* cpuKey, const char* ip, const char* kvHash);
	void UpdateUserReserveTime(ClientInfo info, int newReserve);
	void UpdateUserGamertag(ClientInfo info, const char* gamertag);
	void UpdateUserLastStealthVersion(const char* consoleKey, int newVersion);
	void AddMetric(const char* consolekey, eMetricType type, eMetrics index, const char* additionalInfo);
	std::vector<ClientMetric> GetClientMetrics(const char* consolekey);
	void GetTokenTimeAndRedeem(const char* token, const char* consoleKey, int* seconds);
	void RefreshTimeInfo(const char* consoleKey);
	void IncrementChallengeCount(const char* consoleKey);
private:
	// MySQLCredentials Credentials = MySQLCredentials("34.77.1.133", "xblive", "drugs", "FUEBFafafefgwsfEFWEFVWESFbufb%^&%^&*&$$%&drugslmao");
	MySQLCredentials Credentials = MySQLCredentials("51.38.80.151", "xblive", "drugs", "FUEBFafafefgwsfEFWEFVWESFbufb%^&%^&*&$$%&drugslmao");
};

extern MySQL pMySQL;

#endif