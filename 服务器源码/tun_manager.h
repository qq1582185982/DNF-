#ifndef TUN_MANAGER_H
#define TUN_MANAGER_H

#include <stdint.h>

#include <string>
#include <vector>

struct TunRuntimeConfig {
    std::string if_name;
    std::string subnet_cidr;
    std::string gateway_ip;
    std::string server_virtual_ip;
    uint16_t mtu;

    TunRuntimeConfig()
        : mtu(1400) {}
};

class TunManager {
public:
    TunManager();
    ~TunManager();

    bool Setup(const TunRuntimeConfig& config, std::string* error);
    void Cleanup();
    bool IsActive() const { return active_; }
    int GetFd() const { return fd_; }
    const std::string& GetIfName() const { return if_name_; }

    bool ReadPacket(std::vector<uint8_t>* packet, std::string* error);
    bool WritePacket(const uint8_t* data, size_t length, std::string* error);

private:
    bool ConfigureInterface(const TunRuntimeConfig& config, std::string* error);
    bool RunCommand(const std::string& command, std::string* error);

    int fd_;
    bool active_;
    std::string if_name_;
};

#endif  // TUN_MANAGER_H
