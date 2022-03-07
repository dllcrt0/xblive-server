#include "mysqlHelper.h"

MySQL pMySQL;

bool MySQL::IsFreemode() {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM `vars` WHERE `id` = 1");
		if (db.Execute()) {
			if (db.Read()) {
				auto json = nlohmann::json::parse(db.GetString("vars").c_str());
				if (!json.empty()) {
					if (json["freemode"]) {
						db.Disconnect();
						return json["freemode"].get<bool>();
					}
				}
			}
		}

		db.Disconnect();
	}

	return false;
}

std::vector<XexInfo> MySQL::GetXexInfos() {
	std::vector<XexInfo> xexInfos;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM xex_data");
		if (db.Execute()) {
			if (db.GetNumRows()) {
				while (db.Read()) {
					XexInfo info;
					info.iID = db.GetInt("id");
					info.dwLastVersion = db.GetUInt("latest_version");
					info.strName = db.GetString("name");
					info.strPatchName = db.GetString("patch_name");
					info.dwTitle = db.GetUInt("title");
					info.dwTitleTimestamp = db.GetUInt("title_timestamp");
					info.bEnabled = db.GetBool("enabled");
					info.strEncryptionKey = db.GetString("encryption_key");
					info.bBetaOnly = db.GetBool("beta_only");

					xexInfos.push_back(info);
				}
			}
		}

		db.Disconnect();
	}

	return xexInfos;
}

bool MySQL::GetXexInfo(int id, XexInfo* ptr) {
	if (!ptr) return false;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM xex_data WHERE `id` = ?");
		db.AddArgument(id);
		if (db.Execute()) {
			if (db.Read()) {
				ptr->iID = db.GetInt("id");
				ptr->dwLastVersion = db.GetUInt("latest_version");
				ptr->strName = db.GetString("name");
				ptr->strPatchName = db.GetString("patch_name");
				ptr->dwTitle = db.GetUInt("title");
				ptr->dwTitleTimestamp = db.GetUInt("title_timestamp");
				ptr->bEnabled = db.GetBool("enabled");
				ptr->strEncryptionKey = db.GetString("encryption_key");
				ptr->bBetaOnly = db.GetBool("beta_only");

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

bool MySQL::DoesRedeemTokenExist(char* token, bool* alreadyRedeemed) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM redeem_tokens WHERE `token` = ?");
		db.AddArgument(token);
		if (db.Execute()) {
			if (db.Read()) {
				if (alreadyRedeemed) {
					*alreadyRedeemed = (bool)strcmp(db.GetString("redeemer_console_key").c_str(), "--none--");
				}

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

std::vector<RedeemTokens> MySQL::GetRedeemTokens() {
	std::vector<RedeemTokens> redeemTokens;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM redeem_tokens");
		if (db.Execute()) {
			if (db.GetNumRows()) {
				while (db.Read()) {
					RedeemTokens token;
					token.iID = db.GetInt("id");
					token.strToken = db.GetString("token");
					token.iSecondsToAdd = db.GetInt("seconds_to_add");
					token.strRedeemerConsoleKey = db.GetString("redeemer_console_key");

					redeemTokens.push_back(token);
				}
			}
		}

		db.Disconnect();
	}

	return redeemTokens;
}

std::vector<ClientEndPoint> MySQL::GetAllClientEndPoints() {
	std::vector<ClientEndPoint> endPoints;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM access_tokens");
		if (db.Execute()) {
			if (db.GetNumRows()) {
				while (db.Read()) {
					ClientEndPoint ep;
					ep.bHasReceivedPresence = db.GetBool("has_received_presence");
					ep.strToken = db.GetString("token");
					ep.LastConnection = db.GetInt64("last_connection");
					ep.WelcomeTime = db.GetInt64("welcome_time");
					ep.iConnectionIndex = db.GetInt("connection_index");
					ep.strConsoleKey = db.GetString("console_key");
					ep.iTotalXamChallenges = db.GetInt("total_xam_challenges");
					ep.bUsingNoKV = (bool)db.GetInt("using_no_kv");

					char*_blank;
					ep.dwCurrentTitle = (unsigned int)strtoull((std::string("0x") + db.GetString("current_title")).c_str(), &_blank, 0);

					endPoints.push_back(ep);
				}
			}
		}

		db.Disconnect();
	}

	return endPoints;
}

bool MySQL::GetClientEndPoint(const char* token, ClientEndPoint* ptr) {
	if (!ptr) return false;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM access_tokens WHERE `token` = ?");
		db.AddArgument(token);
		if (db.Execute()) {
			if (db.Read()) {
				ptr->bHasReceivedPresence = db.GetBool("has_received_presence");
				ptr->strToken = db.GetString("token");
				ptr->LastConnection = db.GetInt64("last_connection");
				ptr->WelcomeTime = db.GetInt64("welcome_time");
				ptr->iConnectionIndex = db.GetInt("connection_index");
				ptr->strConsoleKey = db.GetString("console_key");
				ptr->iTotalXamChallenges = db.GetInt("total_xam_challenges");
				ptr->bUsingNoKV = (bool)db.GetInt("using_no_kv");

				char*_blank;
				ptr->dwCurrentTitle = (unsigned int)strtoull((std::string("0x") + db.GetString("current_title")).c_str(), &_blank, 0);

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

void MySQL::DeleteConsoleVerification(const char* cpuKey) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("DELETE FROM console_verification WHERE `cpu_key` = ?");
		db.AddArgument(cpuKey);
		db.Execute();
		db.Disconnect();
	}
}

bool MySQL::GetConsoleVerification(const char* cpuKey, ConsoleVerification* ptr) {
	if (!ptr) return false;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM console_verification WHERE cpu_key = ?");
		db.AddArgument(cpuKey);
		if (db.Execute()) {
			if (db.Read()) {
				ptr->iID = db.GetInt("id");
				ptr->strVerificationKey = db.GetString("verification_key");
				ptr->strCPUKey = db.GetString("cpu_key");
				ptr->iTimeRequested = db.GetInt("time_requested");

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

std::vector<KVs> MySQL::GetKVs() {
	std::vector<KVs> kvs;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM kvs");
		if (db.Execute()) {
			if (db.GetNumRows()) {
				while (db.Read()) {
					KVs kv;
					kv.iID = db.GetInt("id");
					kv.strHash = db.GetString("hash");
					kv.iUses = db.GetInt("uses");
					kvs.push_back(kv);
				}
			}
		}

		db.Disconnect();
	}

	return kvs;
}

bool MySQL::GetClientData(const char* consoleKey, ClientInfo* ptr) {
	if (!ptr) return false;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM users WHERE console_key = ?");
		db.AddArgument(consoleKey);
		if (db.Execute()) {
			if (db.Read()) {
				ptr->iID = db.GetInt("id");
				ptr->bConsoleLinked = db.GetBool("console_linked");
				ptr->bBetaAccess = db.GetBool("beta_access");
				ptr->strConsoleKey = db.GetString("console_key");
				ptr->strCPUKey = db.GetString("cpu");
				ptr->strFirstGamertag = db.GetString("first_gamertag");
				ptr->strLastGamertag = db.GetString("last_gamertag");
				ptr->bDevkitCheats = db.GetBool("devkit_cheats");
				ptr->iTimeEnd = db.GetInt("time_end");
				ptr->iTimeBeforeReserve = db.GetInt("time_before_reserve");
				ptr->iReserveSeconds = db.GetInt("reserve_seconds");
				ptr->strFirstIP = db.GetString("first_ip");
				ptr->strLastIP = db.GetString("last_ip");
				ptr->Status = (eClientInfoStatus)db.GetInt("status");
				ptr->strNotifyOnSus = db.GetString("notify_on_sus");
				ptr->strFirstKVHash = db.GetString("first_kv_hash");
				ptr->strLastKVHash = db.GetString("last_kv_hash");
				ptr->iLastConnection = db.GetInt("last_connection");
				ptr->iTotalChallenges = db.GetInt("total_challenges");
				ptr->iLastUsedVersion = db.GetInt("last_version");
				ptr->bAllowedOnDevkit = db.GetBool("allowed_on_devkit");
				ptr->strNoKVHash = db.GetString("no_kv_hash");
				ptr->iNoKVLastRefresh = db.GetInt("no_kv_last_refresh");

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

bool MySQL::GetClientDataFromID(int id, ClientInfo* ptr) {
	if (!ptr) return false;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM users WHERE `id` = ?");
		db.AddArgument(id);
		if (db.Execute()) {
			if (db.Read()) {
				ptr->iID = db.GetInt("id");
				ptr->bConsoleLinked = db.GetBool("console_linked");
				ptr->bBetaAccess = db.GetBool("beta_access");
				ptr->strConsoleKey = db.GetString("console_key");
				ptr->strCPUKey = db.GetString("cpu");
				ptr->strFirstGamertag = db.GetString("first_gamertag");
				ptr->strLastGamertag = db.GetString("last_gamertag");
				ptr->bDevkitCheats = db.GetBool("devkit_cheats");
				ptr->iTimeEnd = db.GetInt("time_end");
				ptr->iTimeBeforeReserve = db.GetInt("time_before_reserve");
				ptr->iReserveSeconds = db.GetInt("reserve_seconds");
				ptr->strFirstIP = db.GetString("first_ip");
				ptr->strLastIP = db.GetString("last_ip");
				ptr->Status = (eClientInfoStatus)db.GetInt("status");
				ptr->strNotifyOnSus = db.GetString("notify_on_sus");
				ptr->strFirstKVHash = db.GetString("first_kv_hash");
				ptr->strLastKVHash = db.GetString("last_kv_hash");
				ptr->iLastConnection = db.GetInt("last_connection");
				ptr->iTotalChallenges = db.GetInt("total_challenges");
				ptr->iLastUsedVersion = db.GetInt("last_version");
				ptr->bAllowedOnDevkit = db.GetBool("allowed_on_devkit");
				ptr->strNoKVHash = db.GetString("no_kv_hash");
				ptr->iNoKVLastRefresh = db.GetInt("no_kv_last_refresh");

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

bool MySQL::GetKVStats(const char* kvHash, KVStats* ptr) {
	if (!ptr) return false;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM kv_stats WHERE kv_hash = ?");
		db.AddArgument(kvHash);
		if (db.Execute()) {
			if (db.Read()) {
				ptr->iID = db.GetInt("id");
				ptr->strKVHash = db.GetString("kv_hash");
				ptr->iFirstConnection = db.GetInt("first_connection");
				ptr->iLastConnection = db.GetInt("last_connection");
				ptr->bBanned = db.GetBool("banned");
				ptr->iBannedTime = db.GetInt("banned_time");
				ptr->iTotalChallenges = db.GetInt("total_challenges");

				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

void MySQL::UpdateKVStat(const char* kvHash, bool banned) {
	KVStats cur;
	GetKVStats(kvHash, &cur);

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE kv_stats SET last_connection = ?, banned = ?, banned_time = ? WHERE `kv_hash` = ?");
		db.AddArgument(banned ? cur.iLastConnection : Utils::GetTimeStamp());
		db.AddArgument(banned);
		db.AddArgument(banned && !cur.bBanned ? Utils::GetTimeStamp() : cur.iBannedTime);
		db.AddArgument(kvHash);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::AddKVStat(const char* kvHash, int firstConnection, int lastConnection, bool banned, int bannedTime) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("INSERT INTO kv_stats (kv_hash, first_connection, last_connection, banned, banned_time) VALUES (?, ?, ?, ?, ?)");
		db.AddArgument(kvHash);
		db.AddArgument(firstConnection);
		db.AddArgument(lastConnection);
		db.AddArgument(banned);
		db.AddArgument(bannedTime);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::RemoveRequestToken(const char* token) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("DELETE FROM access_tokens WHERE `token` = ?");
		db.AddArgument(token);
		db.Execute();
		db.Disconnect();
	}
}

bool MySQL::DoesRequestTokenExist(const char* token, const char* consoleKey) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM access_tokens WHERE `token` = ? AND `console_key` = ?");
		db.AddArgument(token);
		db.AddArgument(consoleKey);

		if (db.Execute()) {
			if (db.Read()) {
				db.Disconnect();
				return true;
			}
		}

		db.Disconnect();
	}

	return false;
}

void MySQL::AddRequestToken(const char* token, const char* consoleKey) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("INSERT INTO access_tokens (connection_index, `token`, `console_key`, last_connection, welcome_time) VALUES (?, ?, ?, ?, ?)");
		db.AddArgument(1);
		db.AddArgument(token);
		db.AddArgument(consoleKey);
		db.AddArgument(Utils::GetTimeStamp());
		db.AddArgument(Utils::GetTimeStamp());
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateRequestTokenHeartbeat(const char* token) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE access_tokens SET last_connection = ?, has_received_presence = ? WHERE `token` = ?");
		db.AddArgument(Utils::GetTimeStamp());
		db.AddArgument(1);
		db.AddArgument(token);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateUsingKVEndpointStatus(const char* token, bool status) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE access_tokens SET using_no_kv = ? WHERE `token` = ?");
		db.AddArgument(status);
		db.AddArgument(token);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateClientNoKVHash(const char* consoleKey, std::string hash) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE users SET no_kv_hash = ? WHERE `console_key` = ?");
		db.AddArgument(hash.c_str());
		db.AddArgument(consoleKey);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateClientNoKVLastRefresh(const char* consoleKey) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE users SET no_kv_last_refresh = ? WHERE `console_key` = ?");
		db.AddArgument(Utils::GetTimeStamp());
		db.AddArgument(consoleKey);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::IncrementKVUsesCount(std::string hash) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE kvs SET uses=uses+1 WHERE `hash` = ?");
		db.AddArgument(hash.c_str());
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::DecrementKVUsesCount(std::string hash) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE kvs SET uses=uses-1 WHERE `hash` = ?");
		db.AddArgument(hash.c_str());
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::IncrementRequestTokenChallengeCount(const char* token) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE access_tokens SET total_xam_challenges=total_xam_challenges+1 WHERE `token` = ?");
		db.AddArgument(token);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::IncrementRequestTokenConnectionCount(const char* token) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE access_tokens SET connection_index=connection_index+1 WHERE `token` = ?");
		db.AddArgument(token);
		db.Execute();
		db.Disconnect();
	}
}

int MySQL::GetRequestTokenConnectionCount(const char* token) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE access_tokens SET connection_index=connection_index+1 WHERE `token` = ?");
		db.AddArgument(token);

		if (db.Execute()) {
			int count = db.GetInt("connection_index");
			db.Disconnect();
			return count;
		}

		db.Disconnect();
	}

	return 0;
}

void MySQL::BanClient(const char* consoleKey, const char* reason) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE users SET status = ?, notify_on_sus = ? WHERE `console_key` = ?");
		db.AddArgument(Disabled);
		db.AddArgument(reason);
		db.AddArgument(consoleKey);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateUserInfoWelcomePacket(const char* consoleKey, const char* kvhash, const char* ip) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE users SET last_kv_hash = ?, last_ip = ?, last_connection = ? WHERE `console_key` = ?");
		db.AddArgument(kvhash);
		db.AddArgument(ip);
		db.AddArgument(Utils::GetTimeStamp());
		db.AddArgument(consoleKey);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateTokenActiveTitle(const char* token, const char* title) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE access_tokens SET current_title = ? WHERE `token` = ?");
		db.AddArgument(title);
		db.AddArgument(token);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::AddUserWelcomePacket(const char* consoleKey, const char* cpuKey, const char* ip, const char* kvHash) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		if (bFreemode) {
			db.Prepare("INSERT INTO users (console_key, cpu, time_before_freemode, first_ip, last_ip, status, first_kv_hash, last_kv_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
		} else {
			db.Prepare("INSERT INTO users (console_key, cpu, time_end, first_ip, last_ip, status, first_kv_hash, last_kv_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
		}

		db.AddArgument(consoleKey);
		db.AddArgument(cpuKey);
		db.AddArgument(bFreemode ? 604800 : Utils::GetTimeStamp() + 604800);
		db.AddArgument(ip);
		db.AddArgument(ip);
		db.AddArgument(Authed);
		db.AddArgument(kvHash);
		db.AddArgument(kvHash);

		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateUserReserveTime(ClientInfo info, int newReserve) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE users SET reserve_seconds = ? WHERE `console_key` = ?");
		db.AddArgument(newReserve);
		db.AddArgument(info.strConsoleKey.c_str());
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateUserGamertag(ClientInfo info, const char* gamertag) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		if (!strcmp(info.strFirstGamertag.c_str(), "--blankuser--")
			|| !strcmp(info.strFirstGamertag.c_str(), "----------------")) {
			db.Prepare("UPDATE users SET first_gamertag = ?, last_gamertag = ? WHERE `console_key` = ?");
			db.AddArgument(gamertag);
			db.AddArgument(gamertag);
			db.AddArgument(info.strConsoleKey.c_str());
		} else {
			db.Prepare("UPDATE users SET last_gamertag = ? WHERE `console_key` = ?");
			db.AddArgument(gamertag);
			db.AddArgument(info.strConsoleKey.c_str());
		}

		db.Execute();
		db.Disconnect();
	}
}

void MySQL::UpdateUserLastStealthVersion(const char* consoleKey, int newVersion) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("UPDATE users SET last_version = ? WHERE `console_key` = ?");
		db.AddArgument(newVersion);
		db.AddArgument(consoleKey);
		db.Execute();
		db.Disconnect();
	}
}

void MySQL::AddMetric(const char* consolekey, eMetricType type, eMetrics index, const char* additionalInfo) {
	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("INSERT INTO metrics (console_key, metric_type, metric_index, additional_info, `time`) VALUES (?, ?, ?, ?, ?)");
		db.AddArgument(consolekey);
		db.AddArgument(type);
		db.AddArgument(index);
		db.AddArgument(additionalInfo);
		db.AddArgument(Utils::GetTimeStamp());
		db.Execute();
		db.Disconnect();
	}
}

std::vector<ClientMetric> MySQL::GetClientMetrics(const char* consolekey) {
	std::vector<ClientMetric> list;

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM metrics WHERE console_key = ?");
		db.AddArgument(consolekey);

		if (db.Execute()) {
			if (db.GetNumRows()) {
				while (db.Read()) {
					list.push_back(ClientMetric((eMetricType)db.GetInt("metric_type"), (eMetrics)db.GetInt("metric_index")));
				}
			}
		}

		db.Disconnect();
	}

	return list;
}

void MySQL::GetTokenTimeAndRedeem(const char* token, const char* consoleKey, int* seconds) {
	ClientInfo info;
	if (GetClientData(consoleKey, &info)) {
		if (info.Status != Banned && info.Status != Disabled) {
			MySQLConnect db;
			if (db.Connect(Credentials)) {
				db.Prepare("SELECT * FROM redeem_tokens WHERE `token` = ?");
				db.AddArgument(token);
				if (db.Execute()) {
					if (db.Read()) {
						*seconds = db.GetInt("seconds_to_add");
					}
				}

				if (*seconds) {
					db.Prepare("UPDATE redeem_tokens SET redeemer_console_key = ? WHERE `token` = ?");
					db.AddArgument(consoleKey);
					db.AddArgument(token);
					db.Execute();

					db.Prepare("UPDATE users SET time_end = ?, `status` = 0 WHERE `console_key` = ?");
					if (*seconds == INT_MAX) {
						db.AddArgument(INT_MAX);
					} else {
						db.AddArgument(info.iTimeEnd > Utils::GetTimeStamp() ? info.iTimeEnd + *seconds : Utils::GetTimeStamp() + *seconds);
					}

					db.AddArgument(consoleKey);
					db.Execute();
				}

				db.Disconnect();
			}
		}
	}
}

void MySQL::RefreshTimeInfo(const char* consoleKey) {
	ClientInfo info;
	if (GetClientData(consoleKey, &info)) {
		if (info.iReserveSeconds < 300) {
			if (info.iTimeBeforeReserve) {
				if (info.iTimeEnd > Utils::GetTimeStamp()) {
					info.iTimeEnd += info.iTimeBeforeReserve;
				} else {
					info.iTimeEnd = Utils::GetTimeStamp() + info.iTimeBeforeReserve;
				}

				info.iTimeBeforeReserve = 0;

				MySQLConnect db;
				if (db.Connect(Credentials)) {
					db.Prepare("UPDATE `users` SET `time_end` = ?, `time_before_reserve` = ? WHERE `console_key` = ?");
					db.AddArgument(info.iTimeEnd);
					db.AddArgument(info.iTimeBeforeReserve);
					db.AddArgument(consoleKey);
					db.Execute();
					db.Disconnect();
				}
			} else {
				if (info.iTimeEnd < Utils::GetTimeStamp()) {
					if (info.Status == Authed) {
						MySQLConnect db;
						if (db.Connect(Credentials)) {
							db.Prepare("UPDATE `users` SET `status` = ? WHERE `console_key` = ?");
							db.AddArgument(NoTime);
							db.AddArgument(consoleKey);
							db.Execute();
							db.Disconnect();
						}
					}
				}
			}
		}
	}
}

void MySQL::IncrementChallengeCount(const char* consoleKey) {
	std::string lastkvhash = "";

	MySQLConnect db;
	if (db.Connect(Credentials)) {
		db.Prepare("SELECT * FROM users WHERE `console_key` = ?");
		db.AddArgument(consoleKey);

		if (db.Execute()) {
			if (db.Read()) {
				lastkvhash = db.GetString("last_kv_hash");
			}
		}

		db.Prepare("UPDATE users SET total_challenges=total_challenges+1 WHERE `console_key` = ?");
		db.AddArgument(consoleKey);
		db.Execute();

		if (!lastkvhash.empty()) {
			db.Prepare("UPDATE kv_stats SET total_challenges=total_challenges+1 WHERE `kv_hash` = ?");
			db.AddArgument(lastkvhash.c_str());
			db.Execute();
		}

		db.Disconnect();
	}
}