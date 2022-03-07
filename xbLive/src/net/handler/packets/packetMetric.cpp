#include "packetMetric.h"

void ProcessMetrics(const char* consoleKey) {
	std::vector<ClientMetric> metrics = pMySQL.GetClientMetrics(consoleKey);
	if (metrics.size() > 0) {
		int warningCount = 0;
		for (std::size_t i = 0; i < metrics.size(); i++) {
			auto metric = metrics[i];
			if (metric.Type == METRIC_DISABLE_ACCOUNT) {
				pMySQL.BanClient(consoleKey, "Account disabled for suspicious activity");
				std::cout << "[!] Banned " << consoleKey << " for receiving a bannable metric" << std::endl;
			}

			if (metric.Type == METRIC_WARNING) {
				warningCount++;
			}
		}

		metrics.clear();

		if (warningCount >= 5) {
			pMySQL.BanClient(consoleKey, "Account disabled for suspicious activity");
			std::cout << "[!] Banned " << consoleKey << " for receiving 5 warning metrics" << std::endl;
		}
	}
}

void PacketMetric::Handle(BinaryReader reader, Socket serverWriter, Header* header) {
	Log::Connection(header, serverWriter, "PacketMetric");

	unsigned char resp[ENCRYPTION_STRUCT_SIZE];

	BinaryWriter writer = BinaryWriter(resp, sizeof(resp));

	eMetricType type = (eMetricType)reader.ReadInt32();
	eMetrics index = (eMetrics)reader.ReadInt32();
	bool hasInfo = reader.ReadBool();
	const char* additional = reader.ReadChars(0x100);

	if (!hasInfo) {
		additional = "none";
	}

	if (type < METRIC_NONE || type > METRIC_TYPE_END) {
		Log::Error(header, serverWriter, "PacketMetric", "Client send an invalid metric type: " + std::to_string(type));
		goto end;
	}

	if (index < METRICS_NONE || index > METRICS_END) {
		Log::Error(header, serverWriter, "PacketMetric", "Client send an invalid metric index: " + std::to_string(index));
		goto end;
	}

	pMySQL.AddMetric(Utils::BytesToString(header->szConsoleKey, 0x14).c_str(), type, index, additional);
	ProcessMetrics(Utils::BytesToString(header->szConsoleKey, 0x14).c_str());
	Log::Warn(header, serverWriter, "PacketMetric", "Processed metric " + std::to_string(index) + " with type " + std::to_string(type));

end:
	auto encryption = Security::CreateEncryption(&writer, header);
	writer.Clean();

	Security::SendPacket(serverWriter, resp, sizeof(resp), encryption);
}