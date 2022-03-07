#ifndef MYSQL_H
#define MYSQL_H
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include "utils/structs.h"

class MySQLConnect {
public:
	bool Connect(MySQLCredentials Creds);
	void Disconnect();

	void Prepare(const char* pQuery);
	bool Execute();
	bool Read();
	size_t GetNumRows();

	void AddArgument(char* pValue);
	void AddArgument(const char* pValue);
	void AddArgument(int iValue);
	void AddArgument(bool bValue);
	void AddArgument(double dValue);
	void AddArgument(unsigned int dwValue);
	void AddArgument(int64_t value);
	void AddArgument(uint64_t value);

	sql::SQLString GetString(const char* pColumn);
	int GetInt(const char* pColumn);
	bool GetBool(const char* pColumn);
	long double GetDouble(const char* pColumn);
	unsigned int GetUInt(const char* pColumn);
	int64_t GetInt64(const char* pColumn);
	uint64_t GetUInt64(const char* pColumn);
private:
	MySQLCredentials Credentials= MySQLCredentials("51.38.80.151", "xblive", "drugs", "FUEBFafafefgwsfEFWEFVWESFbufb%^&%^&*&$$%&drugslmao");
	int iNumberParams;

	sql::Driver* pDriver;
	sql::Connection* pConnection;
	sql::PreparedStatement* pPreparedStatement;
	sql::ResultSet* pResult;
};

#endif