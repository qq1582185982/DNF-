#pragma once

#include <stdint.h>

#include <string>
#include <vector>

struct LinuxTunConfig {
    std::string if_name;
    std::string virtual_ip;
    std::string subnet_mask;
    std::vector<std::string> routes;
    uint16_t mtu;

    LinuxTunConfig()
        : mtu(1400) {}
};

class LinuxTunManager {
public:
    LinuxTunManager();
    ~LinuxTunManager();

    bool Setup(const LinuxTunConfig& config, std::string* error);
    void Cleanup();

    bool ReadPacket(std::vector<uint8_t>* packet, int timeout_ms, std::string* error);
    bool WritePacket(const uint8_t* data, size_t length, std::string* error);

    bool IsActive() const { return active_; }
    int GetFd() const { return fd_; }
    const std::string& GetIfName() const { return if_name_; }

private:
    bool ConfigureInterface(const LinuxTunConfig& config, std::string* error);
    bool RunCommand(const std::string& command, std::string* error);

    int fd_;
    bool active_;
    std::string if_name_;
};