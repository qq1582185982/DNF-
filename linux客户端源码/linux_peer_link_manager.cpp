#include "linux_peer_link_manager.h"

#include <chrono>

namespace {

uint64_t linux_peer_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}

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

void LinuxPeerLinkManager::TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = linux_peer_now_ms();
}

void LinuxPeerLinkManager::ObservePeerFrame(const std::string& peer_virtual_ip,
                                            uint64_t endpoint_version,
                                            LinuxPeerRouteState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = linux_peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    if (entry.state != state) {
        entry.state = state;
        entry.last_state_change_ms = now;
    }
    if (state != LinuxPeerRouteState::Probing) {
        entry.pending_hello_version = 0;
        entry.pending_hello_nonce = 0;
    }
}

void LinuxPeerLinkManager::RecordPeerHelloSent(const std::string& peer_virtual_ip,
                                               uint64_t endpoint_version,
                                               uint32_t nonce) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = linux_peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    entry.pending_hello_version = endpoint_version;
    entry.pending_hello_nonce = nonce;
    if (entry.state != LinuxPeerRouteState::Probing) {
        entry.state = LinuxPeerRouteState::Probing;
        entry.last_state_change_ms = now;
    }
}

bool LinuxPeerLinkManager::TryPromotePeerDirectReady(const std::string& peer_virtual_ip,
                                                     uint64_t endpoint_version,
                                                     uint32_t nonce) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end()) {
        return false;
    }

    Entry& entry = it->second;
    const uint64_t now = linux_peer_now_ms();
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
    if (entry.state != LinuxPeerRouteState::DirectReady) {
        entry.state = LinuxPeerRouteState::DirectReady;
        entry.last_state_change_ms = now;
    }
    return true;
}

void LinuxPeerLinkManager::MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, LinuxPeerRouteState::Probing);
}

void LinuxPeerLinkManager::MarkPeerDirectReady(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, LinuxPeerRouteState::DirectReady);
}

void LinuxPeerLinkManager::MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    ObservePeerFrame(peer_virtual_ip, endpoint_version, LinuxPeerRouteState::Cooldown);
}

std::vector<LinuxPeerRouteStatus> LinuxPeerLinkManager::ExpireStalePeers(uint64_t now_ms,
                                                                         uint64_t offer_timeout_ms,
                                                                         uint64_t direct_ready_timeout_ms,
                                                                         uint64_t cooldown_timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LinuxPeerRouteStatus> changed;
    for (std::map<std::string, Entry>::iterator it = peers_.begin(); it != peers_.end(); ++it) {
        Entry& entry = it->second;
        LinuxPeerRouteState next_state = entry.state;

        if ((entry.state == LinuxPeerRouteState::OfferReceived || entry.state == LinuxPeerRouteState::Probing) &&
            entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
            (now_ms - entry.last_observed_ms) >= offer_timeout_ms) {
            next_state = LinuxPeerRouteState::Cooldown;
        } else if (entry.state == LinuxPeerRouteState::DirectReady &&
                   entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
                   (now_ms - entry.last_observed_ms) >= direct_ready_timeout_ms) {
            next_state = LinuxPeerRouteState::Cooldown;
        } else if (entry.state == LinuxPeerRouteState::Cooldown &&
                   entry.last_state_change_ms != 0 && now_ms > entry.last_state_change_ms &&
                   (now_ms - entry.last_state_change_ms) >= cooldown_timeout_ms) {
            next_state = LinuxPeerRouteState::RelayOnly;
        }

        if (next_state != entry.state) {
            entry.state = next_state;
            entry.last_state_change_ms = now_ms;
            if (next_state != LinuxPeerRouteState::Probing) {
                entry.pending_hello_version = 0;
                entry.pending_hello_nonce = 0;
            }

            LinuxPeerRouteStatus status;
            status.peer_virtual_ip = it->first;
            status.state = entry.state;
            status.endpoint_version = entry.endpoint_version;
            status.direct_ready = (entry.state == LinuxPeerRouteState::DirectReady);
            status.last_observed_ms = entry.last_observed_ms;
            status.last_state_change_ms = entry.last_state_change_ms;
            changed.push_back(status);
        }
    }
    return changed;
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
        status.last_observed_ms = it->second.last_observed_ms;
        status.last_state_change_ms = it->second.last_state_change_ms;
        snapshot.push_back(status);
    }
    return snapshot;
}
