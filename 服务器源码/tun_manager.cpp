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

    // Keep the gateway address on the interface, but make the local node IP the
    // primary address so kernel source selection converges to server_virtual_ip.
    std::vector<std::string> interface_ips;
    if (!config.server_virtual_ip.empty()) {
        interface_ips.push_back(config.server_virtual_ip);
    }
    if (!config.gateway_ip.empty() && !contains_ip(interface_ips, config.gateway_ip)) {
        interface_ips.push_back(config.gateway_ip);
    }
    for (size_t i = 0; i < config.local_node_ips.size(); ++i) {
        if (!config.local_node_ips[i].empty() &&
            !contains_ip(interface_ips, config.local_node_ips[i])) {
            interface_ips.push_back(config.local_node_ips[i]);
        }
    }

    for (size_t i = 0; i < interface_ips.size(); ++i) {
        std::ostringstream addr_cmd;
        addr_cmd << "ip addr add " << interface_ips[i] << "/" << prefix_length
                 << " dev " << if_name_;
        if (!RunCommand(addr_cmd.str(), error)) {
            return false;
        }
    }

    std::ostringstream link_cmd;
    link_cmd << "ip link set dev " << if_name_ << " up mtu " << config.mtu;
    if (!RunCommand(link_cmd.str(), error)) {
        return false;
    }

    if (!config.server_virtual_ip.empty()) {
        std::ostringstream route_cmd;
        route_cmd << "ip route replace " << config.subnet_cidr
                  << " dev " << if_name_
                  << " src " << config.server_virtual_ip;
        if (!RunCommand(route_cmd.str(), error)) {
            return false;
        }
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
