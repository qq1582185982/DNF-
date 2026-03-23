#include "peer_coord.h"

PeerCoord::PeerCoord() {
}

void PeerCoord::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_.clear();
}

uint64_t PeerCoord::BumpEndpointVersion(const std::string& peer_virtual_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    ++entry.endpoint_version;
    return entry.endpoint_version;
}

void PeerCoord::ObservePeerFrame(const std::string& peer_virtual_ip,
                                 uint64_t endpoint_version,
                                 PeerEndpointState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.state = state;
}

void PeerCoord::SetState(const std::string& peer_virtual_ip, PeerEndpointState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_[peer_virtual_ip].state = state;
}

uint64_t PeerCoord::GetEndpointVersion(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end()) {
        return 0;
    }
    return it->second.endpoint_version;
}

std::vector<PeerCoordStatus> PeerCoord::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerCoordStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        PeerCoordStatus status;
        status.peer_virtual_ip = it->first;
        status.endpoint_version = it->second.endpoint_version;
        status.state = it->second.state;
        snapshot.push_back(status);
    }
    return snapshot;
}
