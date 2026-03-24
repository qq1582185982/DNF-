#include "peer_link_manager.h"

#include <cstring>
#include <windows.h>

namespace {

uint64_t peer_now_ms() {
    return static_cast<uint64_t>(GetTickCount64());
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

bool PeerLinkManager::UpdatePeerOffer(const std::string& peer_virtual_ip,
                                      uint64_t endpoint_version,
                                      uint8_t endpoint_family,
                                      const uint8_t* endpoint_addr,
                                      uint16_t endpoint_port) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = peer_now_ms();
    const bool same_endpoint =
        entry.endpoint_family == endpoint_family &&
        entry.endpoint_port == endpoint_port &&
        memcmp(entry.endpoint_addr, endpoint_addr, sizeof(entry.endpoint_addr)) == 0;
    const bool same_version = (entry.endpoint_version != 0 && endpoint_version == entry.endpoint_version);

    if (entry.endpoint_version != 0 && endpoint_version < entry.endpoint_version) {
        return false;
    }

    if (same_version && same_endpoint) {
        entry.last_observed_ms = now;
        if (entry.state == PeerRouteState::DirectReady) {
            return false;
        }
        if (entry.state == PeerRouteState::Probing &&
            entry.pending_hello_version == endpoint_version &&
            entry.pending_hello_nonce != 0) {
            return false;
        }
    }

    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.endpoint_family = endpoint_family;
    entry.endpoint_port = endpoint_port;
    memset(entry.endpoint_addr, 0, sizeof(entry.endpoint_addr));
    if (endpoint_addr != NULL) {
        memcpy(entry.endpoint_addr, endpoint_addr, sizeof(entry.endpoint_addr));
    }
    entry.last_observed_ms = now;
    if (entry.state != PeerRouteState::OfferReceived) {
        entry.state = PeerRouteState::OfferReceived;
        entry.last_state_change_ms = now;
    }
    return true;
}

void PeerLinkManager::TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = peer_now_ms();
}

void PeerLinkManager::TouchPeerDirectData(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    entry.last_direct_data_ms = now;
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
            status.endpoint_family = entry.endpoint_family;
            status.endpoint_port = entry.endpoint_port;
            memcpy(status.endpoint_addr, entry.endpoint_addr, sizeof(status.endpoint_addr));
            status.direct_ready = (entry.state == PeerRouteState::DirectReady);
            status.last_observed_ms = entry.last_observed_ms;
            status.last_direct_data_ms = entry.last_direct_data_ms;
            status.last_state_change_ms = entry.last_state_change_ms;
            changed.push_back(status);
        }
    }
    return changed;
}

bool PeerLinkManager::CanRouteDirect(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    return it != peers_.end() &&
           it->second.state == PeerRouteState::DirectReady &&
           it->second.endpoint_family != 0 &&
           it->second.endpoint_port != 0;
}

bool PeerLinkManager::TryGetDirectRoute(const std::string& peer_virtual_ip,
                                        uint64_t now_ms,
                                        uint64_t direct_data_timeout_ms,
                                        uint64_t direct_probe_grace_ms,
                                        PeerRouteStatus* out_status) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end() ||
        it->second.state != PeerRouteState::DirectReady ||
        it->second.endpoint_family == 0 ||
        it->second.endpoint_port == 0) {
        return false;
    }

    const bool has_fresh_direct_data =
        it->second.last_direct_data_ms != 0 &&
        now_ms >= it->second.last_direct_data_ms &&
        (now_ms - it->second.last_direct_data_ms) <= direct_data_timeout_ms;
    const bool in_probe_grace =
        it->second.last_state_change_ms != 0 &&
        now_ms >= it->second.last_state_change_ms &&
        (now_ms - it->second.last_state_change_ms) <= direct_probe_grace_ms;
    if (!has_fresh_direct_data && !in_probe_grace) {
        return false;
    }

    if (out_status != NULL) {
        out_status->peer_virtual_ip = it->first;
        out_status->state = it->second.state;
        out_status->endpoint_version = it->second.endpoint_version;
        out_status->endpoint_family = it->second.endpoint_family;
        out_status->endpoint_port = it->second.endpoint_port;
        memcpy(out_status->endpoint_addr, it->second.endpoint_addr, sizeof(out_status->endpoint_addr));
        out_status->direct_ready = true;
        out_status->last_observed_ms = it->second.last_observed_ms;
        out_status->last_direct_data_ms = it->second.last_direct_data_ms;
        out_status->last_state_change_ms = it->second.last_state_change_ms;
    }
    return true;
}

bool PeerLinkManager::TryResolveByEndpoint(uint8_t endpoint_family,
                                           const uint8_t* endpoint_addr,
                                           uint16_t endpoint_port,
                                           PeerRouteStatus* out_status) const {
    if (endpoint_addr == NULL || endpoint_family == 0 || endpoint_port == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        if (it->second.state != PeerRouteState::DirectReady ||
            it->second.endpoint_family != endpoint_family ||
            it->second.endpoint_port != endpoint_port ||
            memcmp(it->second.endpoint_addr, endpoint_addr, sizeof(it->second.endpoint_addr)) != 0) {
            continue;
        }

        if (out_status != NULL) {
            out_status->peer_virtual_ip = it->first;
            out_status->state = it->second.state;
            out_status->endpoint_version = it->second.endpoint_version;
            out_status->endpoint_family = it->second.endpoint_family;
            out_status->endpoint_port = it->second.endpoint_port;
            memcpy(out_status->endpoint_addr, it->second.endpoint_addr, sizeof(out_status->endpoint_addr));
            out_status->direct_ready = true;
            out_status->last_observed_ms = it->second.last_observed_ms;
            out_status->last_direct_data_ms = it->second.last_direct_data_ms;
            out_status->last_state_change_ms = it->second.last_state_change_ms;
        }
        return true;
    }

    return false;
}

std::vector<PeerRouteStatus> PeerLinkManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerRouteStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        PeerRouteStatus status;
        status.peer_virtual_ip = it->first;
        status.state = it->second.state;
        status.endpoint_version = it->second.endpoint_version;
        status.endpoint_family = it->second.endpoint_family;
        status.endpoint_port = it->second.endpoint_port;
        memcpy(status.endpoint_addr, it->second.endpoint_addr, sizeof(status.endpoint_addr));
        status.direct_ready = (it->second.state == PeerRouteState::DirectReady);
        status.last_observed_ms = it->second.last_observed_ms;
        status.last_direct_data_ms = it->second.last_direct_data_ms;
        status.last_state_change_ms = it->second.last_state_change_ms;
        snapshot.push_back(status);
    }
    return snapshot;
}
