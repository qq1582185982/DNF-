#pragma once

#include <stdint.h>

#include <atomic>
#include <string>
#include <vector>

struct LinuxServerInfo {
    int id;
    std::string name;
    std::string server_virtual_ip;
    std::string tunnel_server_ip;
    int tunnel_port;
    std::string virtual_subnet;
    std::string virtual_gateway;
    uint32_t lease_seconds;

    LinuxServerInfo()
        : id(0),
          tunnel_port(0),
          lease_seconds(0) {}
};

std::string NowString();
void LogInfo(const std::string& message);
void LogWarn(const std::string& message);
void LogError(const std::string& message);

std::string GenerateSessionUuid();

std::string ExtractJsonString(const std::string& json, const std::string& key);
int ExtractJsonInt(const std::string& json, const std::string& key, int default_value);
bool ExtractJsonBool(const std::string& json, const std::string& key, bool default_value);
std::vector<std::string> ExtractJsonStringArray(const std::string& json, const std::string& key);
std::vector<std::string> SplitObjectsFromArray(const std::string& json, const std::string& array_key);

bool ParseServerListJson(const std::string& json, std::vector<LinuxServerInfo>* servers, std::string* error);

bool ParseIpv4(const std::string& ip, uint32_t* out_ip_be);
int MaskToPrefix(const std::string& subnet_mask);
std::string PrefixFromCidr(const std::string& cidr);

extern std::atomic<bool> g_linux_client_stop;