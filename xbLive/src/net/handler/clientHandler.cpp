#include "clientHandler.h"
#include "net/handler/packets/packetConnect.h"
#include "net/handler/packets/packetWelcome.h"
#include "net/handler/packets/packetDownloadPlugin.h"
#include "net/handler/packets/packetGetPlugins.h"
#include "net/handler/packets/packetXOSC.h"
#include "net/handler/packets/packetCheckToken.h"
#include "net/handler/packets/packetRedeemToken.h"
#include "net/handler/packets/packetMetric.h"
#include "net/handler/packets/packetHeartbeat.h"
#include "net/handler/packets/packetGetTime.h"
#include "net/handler/packets/packetGetChangelog.h"
#include "net/handler/packets/packetGetUpdate.h"
#include "net/handler/packets/packetGetKVStats.h"
#include "net/handler/packets/packetGetTitlePatches.h"
#include "net/handler/packets/packetGetPluginPatches.h"
#include "net/handler/packets/packetGetChallengeResponse.h"
#include "net/handler/packets/packetBO3.h"
#include "net/handler/packets/packetGetKV.h"

std::vector<std::pair<in_addr_t, SocketSpam>> ClientHandler::SocketSpamConnectionLog;
bool ClientHandler::bUsingSpamDetection;

void ClientHandler::StartFreemodeWatcher() {
	while (true) {
		bFreemode = pMySQL.IsFreemode();
		sleep(60);
	}
}

void ClientHandler::StartHeartbeatHandler() {
	while (true) {
		std::vector<std::pair<std::string, std::string>> tokensToRemove;
		std::vector<ClientEndPoint> endPoints = pMySQL.GetAllClientEndPoints();

		for (std::size_t i = 0; i < endPoints.size(); i++) {
			auto ep = endPoints[i];
			int timestamp = Utils::GetTimeStamp();

			if (!ep.bHasReceivedPresence) {
				if ((timestamp - ep.WelcomeTime) > 600) {
					tokensToRemove.push_back(std::make_pair(ep.strToken, "Hasn't sent initial presence in over 10 minutes"));
					continue;
				}
			}

			if ((timestamp - ep.LastConnection) > 600) {
				tokensToRemove.push_back(std::make_pair(ep.strToken, "Hasn't sent presence in over 10 minutes"));
				continue;
			}
		}

		for (std::size_t i = 0; i < tokensToRemove.size(); i++) {
			auto token = tokensToRemove[i];
			Log::Misc("Deleting token: " + token.first + " - " + token.second);
			pMySQL.RemoveRequestToken(token.first.c_str());
		}

		tokensToRemove.clear();
		endPoints.clear();

		sleep(10);
	}
}

void ClientHandler::StartConnectionLogHandler() {
	while (true) {
		std::vector<std::size_t> indexToRemove;

		for (std::size_t i = 0; i < SocketSpamConnectionLog.size(); i++) {
			auto v = SocketSpamConnectionLog[i];
			if ((Utils::GetTimeStamp() - v.second.InitialTimestamp) > 120) {
				if (!v.second.bBanned) {
					indexToRemove.push_back(i);
				} else {
					if ((Utils::GetTimeStamp() - v.second.InitialTimestamp) > 3600) {
						SocketSpamConnectionLog[i].second.bBanned = false;
						SocketSpamConnectionLog[i].second.BannedTimestamp = 0;

						auto ip = SocketSpamConnectionLog[i].first;
						
						char ipStr[15];
						snprintf(ipStr, 15, "%d.%d.%d.%d", (ip & 0xFF), ((ip & 0xFF00) >> 8), ((ip & 0xFF0000) >> 16), ((ip & 0xFF000000) >> 24));

						Utils::UnbanClient(ipStr);

						SocketSpamConnectionLog.erase(SocketSpamConnectionLog.begin() + i);
					}
				}
			}
		}

		while (bUsingSpamDetection) sleep(1);

		for (std::size_t i = 0; i < indexToRemove.size(); i++) {
			SocketSpamConnectionLog[indexToRemove[i]].second.ConnectionTimestamps.clear();
			SocketSpamConnectionLog.erase(SocketSpamConnectionLog.begin() + indexToRemove[i]);
		}

		indexToRemove.clear();

		sleep(10);
	}
}

void ClientHandler::StartListener() {
	if (Server.StartListener()) {
		sockaddr_in addr;
		while (true) {
			auto length = sizeof(addr);
			auto socket = accept(Server.GetSocket(), (struct sockaddr*)&addr, (socklen_t*)&length);

			ConnectionInfo* client = (ConnectionInfo*)Utils::Alloc(sizeof(ConnectionInfo));
			if (!client) {
				Log::Misc("Failed to allocate ConnectionInfo");
				close(socket);
				continue;
			}

			client->SocketAddress = addr.sin_addr.s_addr;
			client->iSocket = socket;
			snprintf(client->szIP, 15, "%d.%d.%d.%d", (addr.sin_addr.s_addr & 0xFF), ((addr.sin_addr.s_addr & 0xFF00) >> 8), ((addr.sin_addr.s_addr & 0xFF0000) >> 16), ((addr.sin_addr.s_addr & 0xFF000000) >> 24));

			Utils::CreateThread((void*)ClientHandler::Handler, client);

			memset(&addr, 0, sizeof(addr));
		}
	} else {
		Log::Misc("Failed to start listener");
	}
}

bool ClientHandler::IsSpammingSocket(in_addr_t ip) {
	bUsingSpamDetection = true;
	bool exists = false;

	for (std::size_t i = 0; i < SocketSpamConnectionLog.size(); i++) {
		if (SocketSpamConnectionLog[i].first == ip) {
			exists = true;
			if (SocketSpamConnectionLog[i].second.bBanned) {
				bUsingSpamDetection = false;
				return true;
			}

			SocketSpamConnectionLog[i].second.iConnectionsMade++;
			SocketSpamConnectionLog[i].second.ConnectionTimestamps.push_back(Utils::GetTimeStamp());

			int detection = 0;
			auto stamps = SocketSpamConnectionLog[i].second.ConnectionTimestamps;
			
			if (stamps.size() >= 2) {
				for (std::size_t i = 0; i < stamps.size(); i++) {
					if (i == stamps.size() - 1) {
						// last iteration
						break;
					} else {
						if ((stamps[i + 1] - stamps[i]) <= 1) {
							detection++;
						}
					}
				}
			}

			if (detection >= 50) {
				char ipStr[15];
				snprintf(ipStr, 15, "%d.%d.%d.%d", (ip & 0xFF), ((ip & 0xFF00) >> 8), ((ip & 0xFF0000) >> 16), ((ip & 0xFF000000) >> 24));
				Log::Misc("Socket spam detected from " + std::string(ipStr));

				Utils::BanClient(ipStr);

				SocketSpamConnectionLog[i].second.BannedTimestamp = Utils::GetTimeStamp();
				SocketSpamConnectionLog[i].second.bBanned = true;
				bUsingSpamDetection = false;
			}

			break;
		}
	}

	if (!exists) {
		SocketSpamConnectionLog.push_back(std::make_pair(ip, SocketSpam(Utils::GetTimeStamp(), 1, false, 0)));
	}

	bUsingSpamDetection = false;
	return false;
}

void ClientHandler::Handler(ConnectionInfo* pClient) {
	if (pClient) {
		Socket client(pClient->iSocket);

		if (IsSpammingSocket(pClient->SocketAddress)) {
			Log::Misc("Closing socket for " + std::string(pClient->szIP) + " - spam detected!");
			
			client.SendErrorCode(0x1);
			client.Close({ (void*)pClient });
			return;
		}

		client.SetIP(pClient->szIP);

		unsigned char szNeededHeaderData[0x8];
		if (!client.Receive(szNeededHeaderData, 0x8)) {
			Log::Misc("Failed to read header start from " + std::string(pClient->szIP));

			client.SendErrorCode(0x2);
			client.Close({ (void*)pClient });
			return;
		}

		Header* header = (Header*)Utils::Alloc(sizeof(Header));

		BinaryReader baseHeaderParse = BinaryReader(szNeededHeaderData, 0x8);
		header->Command = (ePackets)baseHeaderParse.ReadInt32();
		header->iSize = baseHeaderParse.ReadInt32();
		baseHeaderParse.Clean();

		if (header->Command < PACKET_WELCOME || header->Command > PACKET_END) {
			Log::Misc("Invalid command from " + std::string(pClient->szIP));
			Utils::BanClient(pClient->szIP);

			client.SendErrorCode(0x3);
			client.Close({ (void*)pClient, (void*)header });
			return;
		}

		if (header->iSize < (int)sizeof(Header) || header->iSize > 0x1000) {
			Log::Misc("Invalid size from " + std::string(pClient->szIP));
			Utils::BanClient(pClient->szIP);

			client.SendErrorCode(0x4);
			client.Close({ (void*)pClient, (void*)header });
			return;
		}

		unsigned char* data = (unsigned char*)Utils::Alloc(header->iSize - 8);
		if (!client.Receive(data, header->iSize - 8)) {
			Log::Misc("Failed to read header from " + std::string(pClient->szIP));

			client.SendErrorCode(0x5);
			client.Close({ (void*)pClient, (void*)header, (void*)data });
			return;
		}

		BinaryReader dataReader = BinaryReader(data, header->iSize - 8, BigEndian);
		header->bCPUEncryptionKey = dataReader.ReadByte();
		dataReader.CopyBytes(header->szCPU, 0x10);

		header->bHypervisorCPUEncryptionKey = dataReader.ReadByte();
		dataReader.CopyBytes(header->szHypervisorCPU, 0x10);

		header->bConsoleKeyEncryptionKey = dataReader.ReadByte();
		dataReader.CopyBytes(header->szConsoleKey, 0x14);

		header->bTokenEncryptionKey = dataReader.ReadByte();
		dataReader.CopyBytes(header->szToken, 0x20);

		header->bDevkit = dataReader.ReadBool();

		dataReader.CopyBytes(header->Encryption.szRandomKey, 0x10);
		dataReader.CopyBytes(header->Encryption.szRC4Key, 0x10);
		header->Encryption.iKey1 = dataReader.ReadInt32();
		header->Encryption.iKey2 = dataReader.ReadInt32();
		header->Encryption.iHash = dataReader.ReadInt32();

		for (int i = 0; i < 0x10; i++) {
			header->szCPU[i] ^= header->bCPUEncryptionKey;
			header->szHypervisorCPU[i] ^= header->bHypervisorCPUEncryptionKey;
		}

		for (int i = 0; i < 0x14; i++) {
			header->szConsoleKey[i] ^= header->bConsoleKeyEncryptionKey;
		}

		for (int i = 0; i < 0x20; i++) {
			header->szToken[i] ^= header->bTokenEncryptionKey;
		}

		if (memcmp(header->szCPU, header->szHypervisorCPU, 0x10)) {
			Log::Misc("Non matching cpus from " + std::string(pClient->szIP));

			dataReader.Clean();

			client.SendErrorCode(0x6);
			client.Close({ (void*)pClient, (void*)header, (void*)data });
			return;
		}

		if (header->Command == PACKET_CONNECT) {
			if (header->iSize != 141) {
				Log::Misc("Failed to verify size of PACKET_CONNECT");
				client.SendErrorCode(0x20);
			} else {
				PacketConnect::Handle(dataReader, client, header);
			}
		} else if (header->Command == PACKET_WELCOME) {
			if (header->iSize != 154) {
				Log::Misc("Failed to verify size of PACKET_WELCOME");
				client.SendErrorCode(0x20);
			} else {
				PacketWelcome::Handle(dataReader, client, header);
			}
		} else {
			if (pMySQL.DoesRequestTokenExist(Utils::BytesToString(header->szToken, 0x20).c_str(), Utils::BytesToString(header->szConsoleKey, 0x14).c_str())) {
				pMySQL.IncrementRequestTokenConnectionCount(Utils::BytesToString(header->szToken, 0x20).c_str());
				pMySQL.RefreshTimeInfo(Utils::BytesToString(header->szConsoleKey, 0x14).c_str());

				switch (header->Command) {
					case PACKET_DOWNLOAD_PLUGIN:
						if (header->iSize != 146) {
							Log::Misc("Failed to verify size of PACKET_DOWNLOAD_PLUGIN");
							client.SendErrorCode(0x20);
							break;
						}

						PacketDownloadPlugin::Handle(dataReader, client, header);
						break;

					case PACKET_GET_PLUGINS:
						if (header->iSize != 141) {
							Log::Misc("Failed to verify size of PACKET_GET_PLUGINS");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetPlugins::Handle(dataReader, client, header);
						break;

					case PACKET_XOSC:
						if (header->iSize != 950) {
							Log::Misc("Failed to verify size of PACKET_XOSC");
							client.SendErrorCode(0x20);
							break;
						}

						PacketXOSC::Handle(dataReader, client, header);
						break;

					case PACKET_CHECK_TOKEN:
						if (header->iSize != 153) {
							Log::Misc("Failed to verify size of PACKET_CHECK_TOKEN");
							client.SendErrorCode(0x20);
							break;
						}

						PacketCheckToken::Handle(dataReader, client, header);
						break;

					case PACKET_REDEEM_TOKEN:
						if (header->iSize != 153) {
							Log::Misc("Failed to verify size of PACKET_REDEEM_TOKEN");
							client.SendErrorCode(0x20);
							break;
						}

						PacketRedeemToken::Handle(dataReader, client, header);
						break;

					case PACKET_METRIC:
						if (header->iSize != 406) {
							Log::Misc("Failed to verify size of PACKET_METRIC");
							client.SendErrorCode(0x20);
							break;
						}

						PacketMetric::Handle(dataReader, client, header);
						break;

					case PACKET_HEARTBEAT:
						if (header->iSize != 186) {
							Log::Misc("Failed to verify size of PACKET_HEARTBEAT");
							client.SendErrorCode(0x20);
							break;
						}

						PacketHeartbeat::Handle(dataReader, client, header);
						break;

					case PACKET_GET_TIME:
						if (header->iSize != 141) {
							Log::Misc("Failed to verify size of PACKET_GET_TIME");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetTime::Handle(dataReader, client, header);
						break;

					case PACKET_GET_CHANGELOG:
						if (header->iSize != 145) {
							Log::Misc("Failed to verify size of PACKET_GET_CHANGELOG");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetChangelog::Handle(dataReader, client, header);
						break;

					case PACKET_GET_UPDATE:
						if (header->iSize != 142) {
							Log::Misc("Failed to verify size of PACKET_GET_UPDATE");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetUpdate::Handle(dataReader, client, header);
						break;

					case PACKET_GET_KV_STATS:
						if (header->iSize != 145) {
							Log::Misc("Failed to verify size of PACKET_GET_KV_STATS");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetKVStats::Handle(dataReader, client, header);
						break;

					case PACKET_GET_TITLE_PATCHES:
						if (header->iSize != 149) {
							Log::Misc("Failed to verify size of PACKET_GET_TITLE_PATCHES");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetTitlePatches::Handle(dataReader, client, header);
						break;

					case PACKET_GET_PLUGIN_PATCHES:
						if (header->iSize != 145) {
							Log::Misc("Failed to verify size of PACKET_GET_PLUGIN_PATCHES");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetPluginPatches::Handle(dataReader, client, header);
						break;

					case PACKET_GET_CHALLENGE_RESPONSE:
						if (header->iSize != 176) {
							Log::Misc("Failed to verify size of PACKET_GET_CHALLENGE_RESPONSE");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetChallengeResponse::Handle(dataReader, client, header);
						break;

					case PACKET_BO3_CHALLENGE:
						if (header->iSize != 162) {
							Log::Misc("Failed to verify size of PACKET_BO3_CHALLENGE");
							client.SendErrorCode(0x20);
							break;
						}

						PacketBO3::Handle(dataReader, client, header);
						break;

					case PACKET_GET_KV:
						if (header->iSize != 146) {
							Log::Misc("Failed to verify size of PACKET_GET_KV");
							client.SendErrorCode(0x20);
							break;
						}

						PacketGetKV::Handle(dataReader, client, header);
						break;
				}
			} else {
				Log::Misc("Error: Access token not found - " + Utils::BytesToString(header->szToken, 0x20));
				dataReader.Clean();
				client.SendErrorCode(0x10);
				client.Close({ (void*)pClient, (void*)header, (void*)data });
				return;
			}
		}

		dataReader.Clean();
		client.Close({ (void*)pClient, (void*)header, (void*)data });
	}
}