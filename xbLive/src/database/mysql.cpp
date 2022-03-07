#include "mysql.h"

bool MySQLConnect::Connect(MySQLCredentials Creds) {
	Credentials = Creds;
	pDriver = get_driver_instance();
	pConnection = nullptr;
	pPreparedStatement = nullptr;
	pResult = nullptr;

	try {
		pConnection = pDriver->connect(Credentials.pHost, Credentials.pUsername, Credentials.pPassword);
		if (pConnection) {
			pConnection->setSchema(Credentials.pDatabase);
			return true;
		}

		std::cout << "MySQL err: Couldn't connect!" << std::endl;
	} catch (sql::SQLException &error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}

	return false;
}

void MySQLConnect::Disconnect() {
	if (pConnection) {
		try {
			pConnection->close();
		} catch (sql::SQLException &error) {
			std::cout << "MySQL err: " << error.what() << std::endl;
		}

		delete pConnection;
	}

	if (pPreparedStatement) {
		delete pPreparedStatement;
	}

	if (pResult) {
		delete pResult;
	}
}

void MySQLConnect::Prepare(const char* pQuery) {
	if (!pConnection) {
		std::cout << "no connection on prepare()" << std::endl;
		return;
	}

	pPreparedStatement = pConnection->prepareStatement(pQuery);
	iNumberParams = 0;
}

bool MySQLConnect::Execute() {
	if (!pConnection
		|| !pPreparedStatement) {
		std::cout << "no connection on Execute()" << std::endl;
		return false;
	}

	try {
		pPreparedStatement->execute();
		pResult = pPreparedStatement->getResultSet();
		return true;
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
		return false;
	}
}

bool MySQLConnect::Read() {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		std::cout << "failed read!" << std::endl;
		return false;
	}

	return pResult->next();
}

size_t MySQLConnect::GetNumRows() {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->rowsCount();
}

void MySQLConnect::AddArgument(char* pValue) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setString(iNumberParams, pValue);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(const char* pValue) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setString(iNumberParams, pValue);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(int iValue) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setInt(iNumberParams, iValue);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(bool bValue) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setBoolean(iNumberParams, bValue);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(double dValue) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setDouble(iNumberParams, dValue);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(unsigned int dwValue) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setUInt(iNumberParams, dwValue);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(int64_t value) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setInt64(iNumberParams, value);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

void MySQLConnect::AddArgument(uint64_t value) {
	if (!pConnection
		|| !pPreparedStatement) {
		return;
	}

	iNumberParams++;

	try {
		pPreparedStatement->setUInt64(iNumberParams, value);
	} catch (sql::SQLException& error) {
		std::cout << "MySQL err: " << error.what() << std::endl;
	}
}

sql::SQLString MySQLConnect::GetString(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return "";
	}

	return pResult->getString(pColumn);
}

int MySQLConnect::GetInt(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->getInt(pColumn);
}

bool MySQLConnect::GetBool(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->getBoolean(pColumn);
}

long double MySQLConnect::GetDouble(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->getDouble(pColumn);
}

unsigned int MySQLConnect::GetUInt(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->getUInt(pColumn);
}

int64_t MySQLConnect::GetInt64(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->getInt64(pColumn);
}

uint64_t MySQLConnect::GetUInt64(const char* pColumn) {
	if (!pConnection
		|| !pPreparedStatement
		|| !pResult) {
		return 0;
	}

	return pResult->getUInt64(pColumn);
}