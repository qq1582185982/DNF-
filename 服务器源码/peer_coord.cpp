#include "peer_coord.h"

#include <chrono>

namespace {

uint64_t peer_coord_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}

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
    entry.last_observed_ms = peer_coord_now_ms();
    return entry.endpoint_version;
}

void PeerCoord::TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = peer_coord_now_ms();
}

void PeerCoord::ObservePeerFrame(const std::string& peer_virtual_ip,
                                 uint64_t endpoint_version,
                                 PeerEndpointState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = peer_coord_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    if (entry.state != state) {
        entry.state = state;
        entry.last_state_change_ms = now;
    }
}

void PeerCoord::SetState(const std::string& peer_virtual_ip, PeerEndpointState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    entry.last_observed_ms = peer_coord_now_ms();
    if (entry.state != state) {
        entry.state = state;
        entry.last_state_change_ms = entry.last_observed_ms;
    }
}

std::vector<PeerCoordStatus> PeerCoord::ExpireStalePeers(uint64_t now_ms,
                                                         uint64_t offer_timeout_ms,
                                                         uint64_t active_timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerCoordStatus> changed;
    for (std::map<std::string, Entry>::iterator it = peers_.begin(); it != peers_.end(); ++it) {
        Entry& entry = it->second;
        PeerEndpointState next_state = entry.state;

        if (entry.state == PeerEndpointState::OfferPending &&
            entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
            (now_ms - entry.last_observed_ms) >= offer_timeout_ms) {
            next_state = PeerEndpointState::RelayOnly;
        } else if (entry.state == PeerEndpointState::Active &&
                   entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
                   (now_ms - entry.last_observed_ms) >= active_timeout_ms) {
            next_state = PeerEndpointState::RelayOnly;
        }

        if (next_state != entry.state) {
            entry.state = next_state;
            entry.last_state_change_ms = now_ms;

            PeerCoordStatus status;
            status.peer_virtual_ip = it->first;
            status.endpoint_version = entry.endpoint_version;
            status.state = entry.state;
            status.last_observed_ms = entry.last_observed_ms;
            status.last_state_change_ms = entry.last_state_change_ms;
            changed.push_back(status);
        }
    }
    return changed;
}

uint64_t PeerCoord::GetEndpointVersion(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end()) {
        return 0;
    }
    return it->second.endpoint_version;
}

PeerEndpointState PeerCoord::GetState(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end()) {
        return PeerEndpointState::Unknown;
    }
    return it->second.state;
}

std::vector<PeerCoordStatus> PeerCoord::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerCoordStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        PeerCoordStatus status;
        status.peer_virtual_ip = it->first;
        status.endpoint_version = it->second.endpoint_version;
        status.state = it->second.state;
        status.last_observed_ms = it->second.last_observed_ms;
        status.last_state_change_ms = it->second.last_state_change_ms;
        snapshot.push_back(status);
    }
    return snapshot;
}
