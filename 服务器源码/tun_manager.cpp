#include "tun_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sstream>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

const size_t kMaxPacketSize = 65535;

int extract_prefix_length(const std::string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        return -1;
    }
    return atoi(cidr.substr(slash + 1).c_str());
}

bool contains_ip(const std::vector<std::string>& ips, const std::string& ip) {
    for (size_t i = 0; i < ips.size(); ++i) {
        if (ips[i] == ip) {
            return true;
        }
    }
    return false;
}

}  // namespace

TunManager::TunManager()
    : fd_(-1),
      active_(false) {}

TunManager::~TunManager() {
    Cleanup();
}

bool TunManager::Setup(const TunRuntimeConfig& config, std::string* error) {
    Cleanup();

    fd_ = open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        if (error != NULL) {
            *error = std::string("open /dev/net/tun failed: ") + strerror(errno);
        }
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (!config.if_name.empty()) {
        strncpy(ifr.ifr_name, config.if_name.c_str(), IFNAMSIZ - 1);
    }

    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        if (error != NULL) {
            *error = std::string("TUNSETIFF failed: ") + strerror(errno);
        }
        close(fd_);
        fd_ = -1;
        return false;
    }

    if_name_ = ifr.ifr_name;

    if (!ConfigureInterface(config, error)) {
        Cleanup();
        return false;
    }

    active_ = true;
    return true;
}

void TunManager::Cleanup() {
    active_ = false;
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    if_name_.clear();
}

bool TunManager::ReadPacket(std::vector<uint8_t>* packet, std::string* error) {
    if (packet == NULL) {
        if (error != NULL) {
            *error = "TunManager::ReadPacket packet is null";
        }
        return false;
    }

    packet->resize(kMaxPacketSize);
    ssize_t n = read(fd_, packet->data(), packet->size());
    if (n <= 0) {
        packet->clear();
        if (error != NULL) {
            *error = std::string("read tun packet failed: ") + strerror(errno);
        }
        return false;
    }

    packet->resize((size_t)n);
    return true;
}

bool TunManager::WritePacket(const uint8_t* data, size_t length, std::string* error) {
    if (fd_ < 0 || data == NULL || length == 0) {
        if (error != NULL) {
            *error = "TunManager::WritePacket invalid state";
        }
        return false;
    }

    ssize_t n = write(fd_, data, length);
    if (n != (ssize_t)length) {
        if (error != NULL) {
            *error = std::string("write tun packet failed: ") + strerror(errno);
        }
        return false;
    }
    return true;
}

bool TunManager::ConfigureInterface(const TunRuntimeConfig& config, std::string* error) {
    int prefix_length = extract_prefix_length(config.subnet_cidr);
    if (prefix_length <= 0) {
        if (error != NULL) {
            *error = "invalid subnet cidr: " + config.subnet_cidr;
        }
        return false;
    }

    std::ostringstream flush_cmd;
    flush_cmd << "ip addr flush dev " << if_name_;
    if (!RunCommand(flush_cmd.str(), error)) {
        return false;
    }

    std::ostringstream gateway_cmd;
    gateway_cmd << "ip addr add " << config.gateway_ip << "/" << prefix_length
                << " dev " << if_name_;
    if (!RunCommand(gateway_cmd.str(), error)) {
        return false;
    }

    std::vector<std::string> local_ips = config.local_node_ips;
    if (!config.server_virtual_ip.empty() &&
        config.server_virtual_ip != config.gateway_ip &&
        !contains_ip(local_ips, config.server_virtual_ip)) {
        local_ips.push_back(config.server_virtual_ip);
    }

    for (size_t i = 0; i < local_ips.size(); ++i) {
        if (local_ips[i].empty() || local_ips[i] == config.gateway_ip) {
            continue;
        }

        std::ostringstream local_ip_cmd;
        local_ip_cmd << "ip addr add " << local_ips[i] << "/" << prefix_length
                     << " dev " << if_name_;
        if (!RunCommand(local_ip_cmd.str(), error)) {
            return false;
        }
    }

    std::ostringstream link_cmd;
    link_cmd << "ip link set dev " << if_name_ << " up mtu " << config.mtu;
    if (!RunCommand(link_cmd.str(), error)) {
        return false;
    }

    if (!RunCommand("sysctl -w net.ipv4.ip_forward=1 >/dev/null", error)) {
        return false;
    }

    std::ostringstream sysctl_cmd;
    sysctl_cmd << "sysctl -w net.ipv4.conf." << if_name_ << ".send_redirects=0 >/dev/null";
    if (!RunCommand(sysctl_cmd.str(), error)) {
        return false;
    }

    sysctl_cmd.str("");
    sysctl_cmd.clear();
    sysctl_cmd << "sysctl -w net.ipv4.conf." << if_name_ << ".accept_redirects=0 >/dev/null";
    if (!RunCommand(sysctl_cmd.str(), error)) {
        return false;
    }

    sysctl_cmd.str("");
    sysctl_cmd.clear();
    sysctl_cmd << "sysctl -w net.ipv4.conf." << if_name_ << ".secure_redirects=0 >/dev/null";
    if (!RunCommand(sysctl_cmd.str(), error)) {
        return false;
    }

    return true;
}

bool TunManager::RunCommand(const std::string& command, std::string* error) {
    int ret = system(command.c_str());
    if (ret != 0) {
        if (error != NULL) {
            *error = "command failed: " + command + " (exit=" + std::to_string(ret) + ")";
        }
        return false;
    }
    return true;
}
