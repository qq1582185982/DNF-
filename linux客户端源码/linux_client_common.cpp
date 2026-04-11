#include "linux_client_common.h"

#include <chrono>
#include <arpa/inet.h>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string.h>
#include <time.h>

std::atomic<bool> g_linux_client_stop(false);

namespace {

std::string ExtractRawJsonValue(const std::string& json, const std::string& key) {
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return "";
    }

    pos = json.find(':', pos);
    if (pos == std::string::npos) {
        return "";
    }

    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) {
        ++pos;
    }

    if (pos >= json.size()) {
        return "";
    }

    if (json[pos] == '"') {
        size_t end = pos + 1;
        while (true) {
            end = json.find('"', end);
            if (end == std::string::npos) {
                return "";
            }
            if (json[end - 1] != '\\') {
                break;
            }
            ++end;
        }
        return json.substr(pos, end - pos + 1);
    }

    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']') {
        ++end;
    }
    return json.substr(pos, end - pos);
}

}  // namespace

std::string NowString() {
    const std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    const std::chrono::milliseconds epoch_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    const int millis = static_cast<int>(epoch_ms.count() % 1000);

    const time_t wall_time = std::chrono::system_clock::to_time_t(now);
    struct tm tm_value;
    localtime_r(&wall_time, &tm_value);

    char buffer[32] = {};
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_value);

    std::ostringstream stream;
    stream << buffer << "." << std::setw(3) << std::setfill('0') << millis;
    return stream.str();
}

void LogInfo(const std::string& message) {
    std::cout << NowString() << " [信息] " << message << std::endl;
}

void LogWarn(const std::string& message) {
    std::cout << NowString() << " [警告] " << message << std::endl;
}

void LogError(const std::string& message) {
    std::cerr << NowString() << " [错误] " << message << std::endl;
}

std::string GenerateSessionUuid() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFFu);

    uint32_t a = dist(gen);
    uint32_t b = dist(gen);
    uint32_t c = dist(gen);
    uint32_t d = dist(gen);

    std::ostringstream stream;
    stream << std::hex << std::setfill('0')
           << std::setw(8) << a << "-"
           << std::setw(4) << ((b >> 16) & 0xFFFFu) << "-"
           << std::setw(4) << (b & 0xFFFFu) << "-"
           << std::setw(4) << ((c >> 16) & 0xFFFFu) << "-"
           << std::setw(4) << (c & 0xFFFFu)
           << std::setw(8) << d;
    return stream.str();
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string raw = ExtractRawJsonValue(json, key);
    if (raw.size() < 2 || raw[0] != '"' || raw[raw.size() - 1] != '"') {
        return "";
    }
    return raw.substr(1, raw.size() - 2);
}

int ExtractJsonInt(const std::string& json, const std::string& key, int default_value) {
    std::string raw = ExtractRawJsonValue(json, key);
    if (raw.empty()) {
        return default_value;
    }
    return atoi(raw.c_str());
}

bool ExtractJsonBool(const std::string& json, const std::string& key, bool default_value) {
    std::string raw = ExtractRawJsonValue(json, key);
    if (raw == "true") {
        return true;
    }
    if (raw == "false") {
        return false;
    }
    return default_value;
}

std::vector<std::string> ExtractJsonStringArray(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    const std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return values;
    }

    size_t start = json.find('[', pos);
    size_t end = json.find(']', start);
    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return values;
    }

    pos = start + 1;
    while (pos < end) {
        size_t quote_start = json.find('"', pos);
        if (quote_start == std::string::npos || quote_start >= end) {
            break;
        }
        size_t quote_end = json.find('"', quote_start + 1);
        if (quote_end == std::string::npos || quote_end > end) {
            break;
        }
        values.push_back(json.substr(quote_start + 1, quote_end - quote_start - 1));
        pos = quote_end + 1;
    }

    return values;
}

std::vector<std::string> SplitObjectsFromArray(const std::string& json, const std::string& array_key) {
    std::vector<std::string> objects;
    const std::string search = "\"" + array_key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) {
        return objects;
    }

    size_t start = json.find('[', pos);
    if (start == std::string::npos) {
        return objects;
    }

    int depth = 0;
    size_t object_start = std::string::npos;
    for (size_t i = start + 1; i < json.size(); ++i) {
        char ch = json[i];
        if (ch == '{') {
            if (depth == 0) {
                object_start = i;
            }
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0 && object_start != std::string::npos) {
                objects.push_back(json.substr(object_start, i - object_start + 1));
                object_start = std::string::npos;
            }
        } else if (ch == ']' && depth == 0) {
            break;
        }
    }

    return objects;
}

bool ParseServerListJson(const std::string& json, std::vector<LinuxServerInfo>* servers, std::string* error) {
    if (servers == NULL) {
        if (error != NULL) {
            *error = "servers output is null";
        }
        return false;
    }

    servers->clear();
    std::vector<std::string> objects = SplitObjectsFromArray(json, "servers");
    for (size_t i = 0; i < objects.size(); ++i) {
        LinuxServerInfo server;
        server.id = ExtractJsonInt(objects[i], "id", 0);
        server.name = ExtractJsonString(objects[i], "name");
        server.server_virtual_ip = ExtractJsonString(objects[i], "server_virtual_ip");
        server.tunnel_server_ip = ExtractJsonString(objects[i], "tunnel_server_ip");
        server.tunnel_port = ExtractJsonInt(objects[i], "tunnel_port", 0);
        server.virtual_subnet = ExtractJsonString(objects[i], "virtual_subnet");
        server.virtual_gateway = ExtractJsonString(objects[i], "virtual_gateway");
        server.lease_seconds = (uint32_t)ExtractJsonInt(objects[i], "lease_seconds", 0);

        if (server.id <= 0 || server.tunnel_server_ip.empty() || server.tunnel_port <= 0) {
            continue;
        }

        servers->push_back(server);
    }

    if (servers->empty()) {
        if (error != NULL) {
            *error = "no server entries parsed";
        }
        return false;
    }
    return true;
}

bool ParseIpv4(const std::string& ip, uint32_t* out_ip_be) {
    if (out_ip_be == NULL) {
        return false;
    }

    in_addr addr = {};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }

    *out_ip_be = addr.s_addr;
    return true;
}

int MaskToPrefix(const std::string& subnet_mask) {
    uint32_t mask_be = 0;
    if (!ParseIpv4(subnet_mask, &mask_be)) {
        return -1;
    }

    uint32_t mask = ntohl(mask_be);
    int prefix = 0;
    while ((mask & 0x80000000u) != 0) {
        ++prefix;
        mask <<= 1;
    }
    return prefix;
}

std::string PrefixFromCidr(const std::string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos || slash + 1 >= cidr.size()) {
        return "";
    }
    return cidr.substr(slash + 1);
}
