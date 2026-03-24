#include "linux_peer_link_manager.h"

#include <chrono>
#include <cstring>

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

bool LinuxPeerLinkManager::UpdatePeerOffer(const std::string& peer_virtual_ip,
                                           uint64_t endpoint_version,
                                           uint8_t endpoint_family,
                                           const uint8_t* endpoint_addr,
                                           uint16_t endpoint_port) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = linux_peer_now_ms();
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
        if (entry.state == LinuxPeerRouteState::DirectReady) {
            return false;
        }
        if (entry.state == LinuxPeerRouteState::Probing &&
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
    if (entry.state != LinuxPeerRouteState::OfferReceived) {
        entry.state = LinuxPeerRouteState::OfferReceived;
        entry.last_state_change_ms = now;
    }
    return true;
}

void LinuxPeerLinkManager::TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = linux_peer_now_ms();
}

void LinuxPeerLinkManager::TouchPeerDirectData(const std::string& peer_virtual_ip,
                                               uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = linux_peer_now_ms();
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    entry.last_direct_data_ms = now;
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
            status.endpoint_family = entry.endpoint_family;
            status.endpoint_port = entry.endpoint_port;
            memcpy(status.endpoint_addr, entry.endpoint_addr, sizeof(status.endpoint_addr));
            status.direct_ready = (entry.state == LinuxPeerRouteState::DirectReady);
            status.last_observed_ms = entry.last_observed_ms;
            status.last_direct_data_ms = entry.last_direct_data_ms;
            status.last_state_change_ms = entry.last_state_change_ms;
            changed.push_back(status);
        }
    }
    return changed;
}

bool LinuxPeerLinkManager::CanRouteDirect(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    return it != peers_.end() &&
           it->second.state == LinuxPeerRouteState::DirectReady &&
           it->second.endpoint_family != 0 &&
           it->second.endpoint_port != 0;
}

bool LinuxPeerLinkManager::TryGetDirectRoute(const std::string& peer_virtual_ip,
                                             uint64_t now_ms,
                                             uint64_t direct_data_timeout_ms,
                                             uint64_t direct_probe_grace_ms,
                                             LinuxPeerRouteStatus* out_status) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end() ||
        it->second.state != LinuxPeerRouteState::DirectReady ||
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

bool LinuxPeerLinkManager::TryResolveByEndpoint(uint8_t endpoint_family,
                                                const uint8_t* endpoint_addr,
                                                uint16_t endpoint_port,
                                                LinuxPeerRouteStatus* out_status) const {
    if (endpoint_addr == NULL || endpoint_family == 0 || endpoint_port == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        if (it->second.state != LinuxPeerRouteState::DirectReady ||
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

std::vector<LinuxPeerRouteStatus> LinuxPeerLinkManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LinuxPeerRouteStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        LinuxPeerRouteStatus status;
        status.peer_virtual_ip = it->first;
        status.state = it->second.state;
        status.endpoint_version = it->second.endpoint_version;
        status.endpoint_family = it->second.endpoint_family;
        status.endpoint_port = it->second.endpoint_port;
        memcpy(status.endpoint_addr, it->second.endpoint_addr, sizeof(status.endpoint_addr));
        status.direct_ready = (it->second.state == LinuxPeerRouteState::DirectReady);
        status.last_observed_ms = it->second.last_observed_ms;
        status.last_direct_data_ms = it->second.last_direct_data_ms;
        status.last_state_change_ms = it->second.last_state_change_ms;
        snapshot.push_back(status);
    }
    return snapshot;
}
