#include "linux_peer_link_manager.h"

LinuxPeerLinkManager::LinuxPeerLinkManager() {
}

void LinuxPeerLinkManager::SetLocalVirtualIp(const std::string& virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    local_virtual_ip_ = virtual_ip;
}

void LinuxPeerLinkManager::ResetAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_.clear();
}

void LinuxPeerLinkManager::UpdatePeerOffer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, LinuxPeerRouteState::OfferReceived);
}

void LinuxPeerLinkManager::ObservePeerFrame(const std::string& peer_virtual_ip,
                                            uint64_t endpoint_version,
                                            LinuxPeerRouteState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.state = state;
}

void LinuxPeerLinkManager::MarkPeerProbing(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = LinuxPeerRouteState::Probing;
}

void LinuxPeerLinkManager::MarkPeerDirectReady(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = LinuxPeerRouteState::DirectReady;
}

void LinuxPeerLinkManager::MarkPeerCooldown(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = LinuxPeerRouteState::Cooldown;
}

bool LinuxPeerLinkManager::CanRouteDirect(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    return it != peers_.end() && it->second.state == LinuxPeerRouteState::DirectReady;
}

std::vector<LinuxPeerRouteStatus> LinuxPeerLinkManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LinuxPeerRouteStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        LinuxPeerRouteStatus status;
        status.peer_virtual_ip = it->first;
        status.state = it->second.state;
        status.endpoint_version = it->second.endpoint_version;
        status.direct_ready = (it->second.state == LinuxPeerRouteState::DirectReady);
        snapshot.push_back(status);
    }
    return snapshot;
}
