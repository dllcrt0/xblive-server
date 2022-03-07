#ifndef STRUCTS_H
#define STRUCTS_H
#include <string>
#include <vector>

#define ENCRYPTION_STRUCT_SIZE 44

enum ePackets {
	PACKET_WELCOME = 1,
	PACKET_HEARTBEAT,
	PACKET_GET_TIME,
	PACKET_CHECK_TOKEN,
	PACKET_REDEEM_TOKEN,
	PACKET_GET_CHALLENGE_RESPONSE,
	PACKET_GET_CHANGELOG,
	PACKET_GET_UPDATE,
	PACKET_XOSC,
	PACKET_GET_PLUGINS,
	PACKET_DOWNLOAD_PLUGIN,
	PACKET_GET_KV_STATS,
	PACKET_BO3_CHALLENGE,
	PACKET_GET_TITLE_PATCHES,
	PACKET_GET_PLUGIN_PATCHES,
	PACKET_METRIC,
	PACKET_CONNECT,
	PACKET_GET_KV,
	PACKET_END
};

enum eEndian {
	BigEndian,
	LittleEndian
};

enum eResponseStatus {
	RESPONSE_ERROR,
	RESPONSE_SUCCESS,

	// kv
	RESPONSE_KV_NEW_ALLOCATED,
	RESPONSE_KV_TIMEOUT,

	// welcome
	RESPONSE_WELCOME_REQUIRED_UPDATE,
	RESPONSE_WELCOME_NO_TIME,
	RESPONSE_WELCOME_DISABLED,
	RESPONSE_WELCOME_BANNED,
	RESPONSE_WELCOME_FREEMODE,
};

enum eMetricType {
	METRIC_NONE,
	METRIC_WARNING,
	METRIC_DISABLE_ACCOUNT,
	METRIC_TYPE_END
};

enum eMetrics {
	METRICS_NONE,
	METRICS_INTEGRITY_CHECK_FAILED,
	METRICS_BREAKPOINT,
	METRICS_MODULE_DIGEST_MISMATCH,
	METRICS_END
};

enum eClientInfoStatus {
	Authed,
	NoTime,
	Banned,
	Disabled
};

#pragma pack(push)
#pragma pack(1)
struct SocketSpam {
	int InitialTimestamp;
	int iConnectionsMade;
	bool bBanned;
	int BannedTimestamp;
	std::vector<int> ConnectionTimestamps;

	SocketSpam(int init, int con, bool banned, int bannedInit) {
		InitialTimestamp = init;
		iConnectionsMade = con;
		bBanned = banned;
		BannedTimestamp = bannedInit;
	}
};

struct XexInfo {
	int iID;
	std::string strName;
	std::string strPatchName;
	unsigned int dwLastVersion;
	unsigned int dwTitle;
	unsigned int dwTitleTimestamp;
	bool bEnabled;
	std::string strEncryptionKey;
	bool bBetaOnly;
};

struct RedeemTokens {
	int iID;
	std::string strToken;
	int iSecondsToAdd;
	std::string strRedeemerConsoleKey;
};

struct ClientEndPoint {
	int iID;
	std::string strToken;
	std::string strConsoleKey;
	long LastConnection;
	long WelcomeTime;
	int iConnectionIndex;
	bool bHasReceivedPresence;
	unsigned int dwCurrentTitle;
	int iTotalXamChallenges;
	bool bUsingNoKV;
};

struct ConsoleVerification {
	int iID;
	std::string strVerificationKey;
	std::string strCPUKey;
	int iTimeRequested;
};

struct KVs {
	int iID;
	std::string strHash;
	int iUses;
};

struct ClientInfo {
	int iID;
	std::string strConsoleKey;
	std::string strCPUKey;
	std::string strFirstGamertag;
	std::string strLastGamertag;
	bool bConsoleLinked;
	bool bBetaAccess;
	bool bAllowedOnDevkit;
	bool bDevkitCheats;
	int iTimeEnd;
	int iTimeBeforeReserve;
	int iReserveSeconds;
	std::string strFirstIP;
	std::string strLastIP;
	eClientInfoStatus Status;
	std::string strNotifyOnSus;
	std::string strFirstKVHash;
	std::string strLastKVHash;
	int iLastConnection;
	int iTotalChallenges;
	int iLastUsedVersion;
	std::string strNoKVHash;
	int iNoKVLastRefresh;
};

struct KVStats {
	int iID;
	std::string strKVHash;
	int iFirstConnection;
	int iLastConnection;
	bool bBanned;
	int iBannedTime;
	int iTotalChallenges;
};

struct ClientMetric {
	eMetricType Type;
	eMetrics Index;

	ClientMetric() {}

	ClientMetric(eMetricType type, eMetrics index) {
		Type = type;
		Index = index;
	}
};

struct EncryptionHeader {
	unsigned char szRandomKey[0x10];
	unsigned char szRC4Key[0x10];
	int iKey1;
	int iKey2;
	int iHash;
};

struct Header {
	ePackets Command;
	int iSize;
	unsigned char bCPUEncryptionKey;
	unsigned char szCPU[0x10];
	unsigned char bHypervisorCPUEncryptionKey;
	unsigned char szHypervisorCPU[0x10];
	unsigned char bConsoleKeyEncryptionKey;
	unsigned char szConsoleKey[0x14];
	unsigned char bTokenEncryptionKey;
	unsigned char szToken[0x20];
	bool bDevkit;
	EncryptionHeader Encryption;
};

struct ConnectionInfo {
	uint32_t SocketAddress;
	int iSocket;
	char szIP[15];
};

struct MySQLCredentials {
	const char* pHost;
	const char* pDatabase;
	const char* pUsername;
	const char* pPassword;

	MySQLCredentials() {}

	MySQLCredentials(const char* host, const char* db, const char* user, const char* pass) {
		pHost = host;
		pDatabase = db;
		pUsername = user;
		pPassword = pass;
	}
};

struct TimeCalc {
	int iYears;
	int iDays;
	int iHours;
	int iMinutes;
	int iSeconds;

	TimeCalc(int iSeconds_) {
		iYears = abs(iSeconds_ / (60 * 60 * 24 * 365));
		iDays = iSeconds_ / 86400;
		iHours = (iSeconds_ % 86400) / 3600;
		iMinutes = ((iSeconds_ % 86400) % 3600) / 60;
		iSeconds = (((iSeconds_ % 86400) % 3600) % 60) / 1;
	}
};
#pragma pack(pop)
#endif