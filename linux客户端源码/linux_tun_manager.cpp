#include "linux_tun_manager.h"

#include "linux_client_common.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <sstream>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

const size_t kMaxPacketSize = 65535;

}  // namespace

LinuxTunManager::LinuxTunManager()
    : fd_(-1),
      active_(false) {}

LinuxTunManager::~LinuxTunManager() {
    Cleanup();
}

bool LinuxTunManager::Setup(const LinuxTunConfig& config, std::string* error) {
    Cleanup();

    fd_ = open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        if (error != NULL) {
            *error = std::string("open /dev/net/tun failed: ") + strerror(errno);
        }
        return false;
    }

    ifreq ifr = {};
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

void LinuxTunManager::Cleanup() {
    active_ = false;
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    if_name_.clear();
}

bool LinuxTunManager::ReadPacket(std::vector<uint8_t>* packet, int timeout_ms, std::string* error) {
    if (packet == NULL) {
        if (error != NULL) {
            *error = "packet output is null";
        }
        return false;
    }

    if (fd_ < 0) {
        if (error != NULL) {
            *error = "tun fd is invalid";
        }
        return false;
    }

    pollfd pfd = {};
    pfd.fd = fd_;
    pfd.events = POLLIN;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret == 0) {
        if (error != NULL) {
            error->clear();
        }
        packet->clear();
        return false;
    }
    if (ret < 0) {
        if (error != NULL) {
            *error = std::string("poll tun failed: ") + strerror(errno);
        }
        packet->clear();
        return false;
    }

    packet->resize(kMaxPacketSize);
    ssize_t n = read(fd_, packet->data(), packet->size());
    if (n <= 0) {
        packet->clear();
        if (error != NULL) {
            *error = std::string("read tun failed: ") + strerror(errno);
        }
        return false;
    }

    packet->resize((size_t)n);
    return true;
}

bool LinuxTunManager::WritePacket(const uint8_t* data, size_t length, std::string* error) {
    if (fd_ < 0 || data == NULL || length == 0) {
        if (error != NULL) {
            *error = "invalid tun write state";
        }
        return false;
    }

    ssize_t n = write(fd_, data, length);
    if (n != (ssize_t)length) {
        if (error != NULL) {
            *error = std::string("write tun failed: ") + strerror(errno);
        }
        return false;
    }
    return true;
}

bool LinuxTunManager::ConfigureInterface(const LinuxTunConfig& config, std::string* error) {
    int prefix = MaskToPrefix(config.subnet_mask);
    if (prefix <= 0) {
        if (error != NULL) {
            *error = "invalid subnet mask: " + config.subnet_mask;
        }
        return false;
    }

    std::ostringstream cmd;
    cmd << "ip addr flush dev " << if_name_;
    if (!RunCommand(cmd.str(), error)) {
        return false;
    }

    cmd.str("");
    cmd.clear();
    cmd << "ip addr add " << config.virtual_ip << "/" << prefix << " dev " << if_name_;
    if (!RunCommand(cmd.str(), error)) {
        return false;
    }

    cmd.str("");
    cmd.clear();
    cmd << "ip link set dev " << if_name_ << " up mtu " << config.mtu;
    if (!RunCommand(cmd.str(), error)) {
        return false;
    }

    cmd.str("");
    cmd.clear();
    cmd << "sysctl -w net.ipv4.conf." << if_name_ << ".send_redirects=0 >/dev/null";
    if (!RunCommand(cmd.str(), error)) {
        return false;
    }

    cmd.str("");
    cmd.clear();
    cmd << "sysctl -w net.ipv4.conf." << if_name_ << ".accept_redirects=0 >/dev/null";
    if (!RunCommand(cmd.str(), error)) {
        return false;
    }

    cmd.str("");
    cmd.clear();
    cmd << "sysctl -w net.ipv4.conf." << if_name_ << ".secure_redirects=0 >/dev/null";
    if (!RunCommand(cmd.str(), error)) {
        return false;
    }

    for (size_t i = 0; i < config.routes.size(); ++i) {
        cmd.str("");
        cmd.clear();
        cmd << "ip route replace " << config.routes[i] << " dev " << if_name_;
        if (!RunCommand(cmd.str(), error)) {
            return false;
        }
    }

    return true;
}

bool LinuxTunManager::RunCommand(const std::string& command, std::string* error) {
    int ret = system(command.c_str());
    if (ret != 0) {
        if (error != NULL) {
            *error = "command failed: " + command + " (exit=" + std::to_string(ret) + ")";
        }
        return false;
    }
    return true;
}
