#include "peer_link_manager.h"

PeerLinkManager::PeerLinkManager() {
}

void PeerLinkManager::SetLocalVirtualIp(const std::string& virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    local_virtual_ip_ = virtual_ip;
}

void PeerLinkManager::ResetAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_.clear();
}

void PeerLinkManager::UpdatePeerOffer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, PeerRouteState::OfferReceived);
}

void PeerLinkManager::ObservePeerFrame(const std::string& peer_virtual_ip,
                                       uint64_t endpoint_version,
                                       PeerRouteState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.state = state;
}

void PeerLinkManager::MarkPeerProbing(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = PeerRouteState::Probing;
}

void PeerLinkManager::MarkPeerDirectReady(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = PeerRouteState::DirectReady;
}

void PeerLinkManager::MarkPeerCooldown(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = PeerRouteState::Cooldown;
}

bool PeerLinkManager::CanRouteDirect(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    return it != peers_.end() && it->second.state == PeerRouteState::DirectReady;
}

std::vector<PeerRouteStatus> PeerLinkManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerRouteStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        PeerRouteStatus status;
        status.peer_virtual_ip = it->first;
        status.state = it->second.state;
        status.endpoint_version = it->second.endpoint_version;
        status.direct_ready = (it->second.state == PeerRouteState::DirectReady);
        snapshot.push_back(status);
    }
    return snapshot;
}
