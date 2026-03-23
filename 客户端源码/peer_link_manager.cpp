#include "peer_link_manager.h"

#include <chrono>

namespace {

uint64_t peer_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}

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

void PeerLinkManager::TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = peer_now_ms();
}

void PeerLinkManager::ObservePeerFrame(const std::string& peer_virtual_ip,
                                       uint64_t endpoint_version,
                                       PeerRouteState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    if (entry.state != state) {
        entry.state = state;
        entry.last_state_change_ms = now;
    }
    if (state != PeerRouteState::Probing) {
        entry.pending_hello_version = 0;
        entry.pending_hello_nonce = 0;
    }
}

void PeerLinkManager::RecordPeerHelloSent(const std::string& peer_virtual_ip,
                                          uint64_t endpoint_version,
                                          uint32_t nonce) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    entry.pending_hello_version = endpoint_version;
    entry.pending_hello_nonce = nonce;
    if (entry.state != PeerRouteState::Probing) {
        entry.state = PeerRouteState::Probing;
        entry.last_state_change_ms = now;
    }
}

bool PeerLinkManager::TryPromotePeerDirectReady(const std::string& peer_virtual_ip,
                                                uint64_t endpoint_version,
                                                uint32_t nonce) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end()) {
        return false;
    }

    Entry& entry = it->second;
    const uint64_t now = peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;

    if (entry.pending_hello_version != endpoint_version ||
        entry.pending_hello_nonce != nonce) {
        return false;
    }

    entry.pending_hello_version = 0;
    entry.pending_hello_nonce = 0;
    if (entry.state != PeerRouteState::DirectReady) {
        entry.state = PeerRouteState::DirectReady;
        entry.last_state_change_ms = now;
    }
    return true;
}

void PeerLinkManager::MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, PeerRouteState::Probing);
}

void PeerLinkManager::MarkPeerDirectReady(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, PeerRouteState::DirectReady);
}

void PeerLinkManager::MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, PeerRouteState::Cooldown);
}

std::vector<PeerRouteStatus> PeerLinkManager::ExpireStalePeers(uint64_t now_ms,
                                                               uint64_t offer_timeout_ms,
                                                               uint64_t direct_ready_timeout_ms,
                                                               uint64_t cooldown_timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerRouteStatus> changed;
    for (std::map<std::string, Entry>::iterator it = peers_.begin(); it != peers_.end(); ++it) {
        Entry& entry = it->second;
        PeerRouteState next_state = entry.state;

        if ((entry.state == PeerRouteState::OfferReceived || entry.state == PeerRouteState::Probing) &&
            entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
            (now_ms - entry.last_observed_ms) >= offer_timeout_ms) {
            next_state = PeerRouteState::Cooldown;
        } else if (entry.state == PeerRouteState::DirectReady &&
                   entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
                   (now_ms - entry.last_observed_ms) >= direct_ready_timeout_ms) {
            next_state = PeerRouteState::Cooldown;
        } else if (entry.state == PeerRouteState::Cooldown &&
                   entry.last_state_change_ms != 0 && now_ms > entry.last_state_change_ms &&
                   (now_ms - entry.last_state_change_ms) >= cooldown_timeout_ms) {
            next_state = PeerRouteState::RelayOnly;
        }

        if (next_state != entry.state) {
            entry.state = next_state;
            entry.last_state_change_ms = now_ms;
            if (next_state != PeerRouteState::Probing) {
                entry.pending_hello_version = 0;
                entry.pending_hello_nonce = 0;
            }

            PeerRouteStatus status;
            status.peer_virtual_ip = it->first;
            status.state = entry.state;
            status.endpoint_version = entry.endpoint_version;
            status.direct_ready = (entry.state == PeerRouteState::DirectReady);
            status.last_observed_ms = entry.last_observed_ms;
            status.last_state_change_ms = entry.last_state_change_ms;
            changed.push_back(status);
        }
    }
    return changed;
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
        status.last_observed_ms = it->second.last_observed_ms;
        status.last_state_change_ms = it->second.last_state_change_ms;
        snapshot.push_back(status);
    }
    return snapshot;
}
