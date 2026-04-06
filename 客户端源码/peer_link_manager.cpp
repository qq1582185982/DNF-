#include "peer_link_manager.h"

#include <cstring>
#include <windows.h>

namespace {

const uint64_t kPeerDirectEligibilityStableMs = 3000;
const uint32_t kPeerDirectEligibilitySamples = 3;
const uint64_t kPeerDirectSampleResetMs = 8000;
const uint64_t kPeerDirectActivationFreshMs = 5000;
const uint32_t kPeerDirectProbeFailureThreshold = 6;
const uint32_t kPeerDirectActiveFailureThreshold = 3;
const uint64_t kPeerDirectRouteFreezeMs = 30000;
const uint64_t kPeerDirectCooldownHoldMs = 30000;

uint64_t peer_now_ms() {
    return static_cast<uint64_t>(GetTickCount64());
}

}

PeerLinkManager::PeerLinkManager() {
}

bool PeerLinkManager::HasEndpoint(const Entry& entry) {
    return entry.endpoint_family != 0 && entry.endpoint_port != 0;
}

bool PeerLinkManager::CanActivateDirect(const Entry& entry, uint64_t now_ms) {
    if (!entry.direct_ready || !HasEndpoint(entry)) {
        return false;
    }
    if (entry.acked_at_ms == 0 || now_ms < entry.acked_at_ms ||
        (now_ms - entry.acked_at_ms) < kPeerDirectEligibilityStableMs) {
        return false;
    }
    if (entry.first_direct_data_ms == 0 || now_ms < entry.first_direct_data_ms ||
        (now_ms - entry.first_direct_data_ms) < kPeerDirectEligibilityStableMs) {
        return false;
    }
    if (entry.direct_sample_count < kPeerDirectEligibilitySamples) {
        return false;
    }
    if (entry.last_direct_failure_ms != 0 && now_ms >= entry.last_direct_failure_ms &&
        (now_ms - entry.last_direct_failure_ms) < kPeerDirectEligibilityStableMs) {
        return false;
    }
    if (entry.retry_after_ms != 0 && now_ms < entry.retry_after_ms) {
        return false;
    }
    return true;
}

void PeerLinkManager::ResetPendingHello(Entry* entry) {
    if (entry == NULL) {
        return;
    }
    entry->pending_hello_version = 0;
    entry->pending_hello_nonce = 0;
}

void PeerLinkManager::ResetDirectAssessment(Entry* entry) {
    if (entry == NULL) {
        return;
    }
    entry->last_direct_data_ms = 0;
    entry->acked_at_ms = 0;
    entry->first_direct_data_ms = 0;
    entry->last_direct_failure_ms = 0;
    entry->freeze_until_ms = 0;
    entry->direct_sample_count = 0;
    entry->probe_failures = 0;
    entry->active_failures = 0;
    entry->direct_ready = false;
    entry->direct_eligible = false;
    entry->active_direct = false;
    ResetPendingHello(entry);
}

void PeerLinkManager::EnterState(Entry* entry, PeerRouteState next_state, uint64_t now_ms) {
    if (entry == NULL) {
        return;
    }
    if (entry->state != next_state) {
        entry->state = next_state;
        entry->last_state_change_ms = now_ms;
    }
}

void PeerLinkManager::EnterCooldown(Entry* entry, uint64_t now_ms) {
    if (entry == NULL) {
        return;
    }

    ResetPendingHello(entry);
    entry->direct_ready = false;
    entry->direct_eligible = false;
    entry->active_direct = false;
    entry->acked_at_ms = 0;
    entry->first_direct_data_ms = 0;
    entry->freeze_until_ms = 0;
    entry->direct_sample_count = 0;
    entry->probe_failures = 0;
    entry->active_failures = 0;
    entry->retry_after_ms = now_ms + kPeerDirectCooldownHoldMs;
    EnterState(entry, PeerRouteState::Cooldown, now_ms);
}

void PeerLinkManager::FillStatus(const std::string& peer_virtual_ip,
                                 const Entry& entry,
                                 PeerRouteStatus* out_status) {
    if (out_status == NULL) {
        return;
    }

    out_status->peer_virtual_ip = peer_virtual_ip;
    out_status->state = entry.state;
    out_status->endpoint_version = entry.endpoint_version;
    out_status->endpoint_family = entry.endpoint_family;
    out_status->endpoint_port = entry.endpoint_port;
    memcpy(out_status->endpoint_addr, entry.endpoint_addr, sizeof(entry.endpoint_addr));
    out_status->direct_ready = entry.direct_ready;
    out_status->direct_eligible = entry.direct_eligible;
    out_status->active_direct = entry.active_direct;
    out_status->last_observed_ms = entry.last_observed_ms;
    out_status->last_direct_data_ms = entry.last_direct_data_ms;
    out_status->last_state_change_ms = entry.last_state_change_ms;
    out_status->acked_at_ms = entry.acked_at_ms;
    out_status->first_direct_data_ms = entry.first_direct_data_ms;
    out_status->last_direct_failure_ms = entry.last_direct_failure_ms;
    out_status->freeze_until_ms = entry.freeze_until_ms;
    out_status->retry_after_ms = entry.retry_after_ms;
    out_status->direct_sample_count = entry.direct_sample_count;
    out_status->probe_failures = entry.probe_failures;
    out_status->active_failures = entry.active_failures;
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
    uint8_t normalized_addr[16] = {};
    if (endpoint_addr != NULL) {
        memcpy(normalized_addr, endpoint_addr, sizeof(normalized_addr));
    }

    const bool same_endpoint =
        entry.endpoint_family == endpoint_family &&
        entry.endpoint_port == endpoint_port &&
        memcmp(entry.endpoint_addr, normalized_addr, sizeof(entry.endpoint_addr)) == 0;
    const bool same_version = (entry.endpoint_version != 0 && endpoint_version == entry.endpoint_version);

    if (entry.endpoint_version != 0 && endpoint_version < entry.endpoint_version) {
        return false;
    }

    entry.last_observed_ms = now;

    if (same_version && same_endpoint) {
        if (entry.state == PeerRouteState::Cooldown &&
            entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
            return false;
        }
        if ((entry.state == PeerRouteState::Probing &&
             entry.pending_hello_version == endpoint_version &&
             entry.pending_hello_nonce != 0) ||
            entry.direct_ready ||
            entry.active_direct) {
            return false;
        }
    }

    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.endpoint_family = endpoint_family;
    entry.endpoint_port = endpoint_port;
    memcpy(entry.endpoint_addr, normalized_addr, sizeof(entry.endpoint_addr));

    if (entry.state == PeerRouteState::Cooldown &&
        entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
        return false;
    }

    ResetDirectAssessment(&entry);
    entry.retry_after_ms = 0;
    EnterState(&entry, PeerRouteState::OfferReceived, now);
    return true;
}

bool PeerLinkManager::ObserveDirectEndpoint(const std::string& peer_virtual_ip,
                                            uint8_t endpoint_family,
                                            const uint8_t* endpoint_addr,
                                            uint16_t endpoint_port,
                                            bool* endpoint_changed,
                                            PeerRouteStatus* out_status) {
    if (endpoint_changed != NULL) {
        *endpoint_changed = false;
    }
    if (endpoint_addr == NULL || endpoint_family == 0 || endpoint_port == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end()) {
        return false;
    }

    Entry& entry = it->second;
    if (entry.endpoint_version == 0) {
        return false;
    }

    const uint64_t now = peer_now_ms();
    const bool changed =
        entry.endpoint_family != endpoint_family ||
        entry.endpoint_port != endpoint_port ||
        memcmp(entry.endpoint_addr, endpoint_addr, sizeof(entry.endpoint_addr)) != 0;

    entry.last_observed_ms = now;
    if (changed) {
        entry.endpoint_family = endpoint_family;
        entry.endpoint_port = endpoint_port;
        memcpy(entry.endpoint_addr, endpoint_addr, sizeof(entry.endpoint_addr));
        if (entry.direct_ready &&
            entry.state != PeerRouteState::DirectActive &&
            entry.state != PeerRouteState::Cooldown) {
            EnterState(&entry, PeerRouteState::Probing, now);
        }
    }

    FillStatus(it->first, entry, out_status);
    if (endpoint_changed != NULL) {
        *endpoint_changed = changed;
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
    const uint64_t previous_direct_data_ms = entry.last_direct_data_ms;
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    entry.probe_failures = 0;
    entry.active_failures = 0;

    if (!entry.direct_ready || entry.state == PeerRouteState::Cooldown ||
        (entry.retry_after_ms != 0 && now < entry.retry_after_ms)) {
        entry.last_direct_data_ms = now;
        return;
    }

    if (entry.first_direct_data_ms == 0 ||
        now < entry.first_direct_data_ms ||
        (previous_direct_data_ms != 0 &&
         now >= previous_direct_data_ms &&
         (now - previous_direct_data_ms) > kPeerDirectSampleResetMs)) {
        entry.first_direct_data_ms = now;
        entry.direct_sample_count = 1;
    } else if (entry.direct_sample_count != 0xFFFFFFFFu) {
        entry.direct_sample_count++;
    }
    entry.last_direct_data_ms = now;

    if (!entry.active_direct && CanActivateDirect(entry, now)) {
        entry.direct_eligible = true;
        entry.active_direct = true;
        entry.freeze_until_ms = now + kPeerDirectRouteFreezeMs;
        EnterState(&entry, PeerRouteState::DirectActive, now);
    }
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

    if (state == PeerRouteState::Cooldown) {
        EnterCooldown(&entry, now);
        return;
    }

    if (state == PeerRouteState::Probing) {
        if (entry.state != PeerRouteState::DirectActive) {
            EnterState(&entry, PeerRouteState::Probing, now);
        }
        return;
    }

    EnterState(&entry, state, now);
    if (state != PeerRouteState::Probing) {
        ResetPendingHello(&entry);
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

    if (entry.state == PeerRouteState::Cooldown &&
        entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
        return;
    }

    ResetDirectAssessment(&entry);
    entry.retry_after_ms = 0;
    entry.pending_hello_version = entry.endpoint_version;
    entry.pending_hello_nonce = nonce;
    EnterState(&entry, PeerRouteState::Probing, now);
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

    ResetPendingHello(&entry);
    entry.direct_ready = HasEndpoint(entry);
    entry.direct_eligible = false;
    entry.active_direct = false;
    entry.acked_at_ms = now;
    entry.first_direct_data_ms = 0;
    entry.last_direct_failure_ms = 0;
    entry.freeze_until_ms = 0;
    entry.direct_sample_count = 0;
    entry.probe_failures = 0;
    entry.active_failures = 0;
    EnterState(&entry, PeerRouteState::Probing, now);
    return entry.direct_ready;
}

void PeerLinkManager::MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = peer_now_ms();
    const uint64_t previous_version = entry.endpoint_version;
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;

    if (entry.state == PeerRouteState::Cooldown &&
        entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
        return;
    }

    if (entry.state == PeerRouteState::DirectActive && endpoint_version > previous_version) {
        ResetDirectAssessment(&entry);
        entry.retry_after_ms = 0;
        EnterState(&entry, PeerRouteState::Probing, now);
        return;
    }

    if (entry.state != PeerRouteState::DirectActive) {
        EnterState(&entry, PeerRouteState::Probing, now);
    }
}

void PeerLinkManager::MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = peer_now_ms();
    EnterCooldown(&entry, entry.last_observed_ms);
}

bool PeerLinkManager::RecordDirectSendFailure(const std::string& peer_virtual_ip,
                                              uint64_t endpoint_version,
                                              bool active_path,
                                              PeerRouteStatus* out_status) {
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
    entry.last_direct_failure_ms = now;

    const PeerRouteState previous_state = entry.state;
    if (active_path && entry.active_direct) {
        if (entry.active_failures != 0xFFFFFFFFu) {
            entry.active_failures++;
        }
        if (entry.active_failures >= kPeerDirectActiveFailureThreshold) {
            EnterCooldown(&entry, now);
        } else {
            entry.direct_eligible = false;
            entry.active_direct = false;
            entry.freeze_until_ms = 0;
            entry.first_direct_data_ms = 0;
            entry.direct_sample_count = 0;
            EnterState(&entry, PeerRouteState::Probing, now);
        }
    } else {
        entry.direct_eligible = false;
        entry.active_direct = false;
        entry.freeze_until_ms = 0;
        entry.first_direct_data_ms = 0;
        entry.direct_sample_count = 0;
        if (entry.probe_failures != 0xFFFFFFFFu) {
            entry.probe_failures++;
        }
        if (entry.probe_failures >= kPeerDirectProbeFailureThreshold) {
            EnterCooldown(&entry, now);
        } else if (entry.state != PeerRouteState::Cooldown) {
            EnterState(&entry, PeerRouteState::Probing, now);
        }
    }

    FillStatus(it->first, entry, out_status);
    return entry.state != previous_state;
}

std::vector<PeerRouteStatus> PeerLinkManager::ExpireStalePeers(uint64_t now_ms,
                                                               uint64_t offer_timeout_ms,
                                                               uint64_t direct_ready_timeout_ms,
                                                               uint64_t cooldown_timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerRouteStatus> changed;
    for (std::map<std::string, Entry>::iterator it = peers_.begin(); it != peers_.end(); ++it) {
        Entry& entry = it->second;
        const PeerRouteState previous_state = entry.state;

        if (!entry.active_direct &&
            entry.state == PeerRouteState::Probing &&
            entry.last_direct_data_ms != 0 &&
            now_ms >= entry.last_direct_data_ms &&
            (now_ms - entry.last_direct_data_ms) <= kPeerDirectActivationFreshMs &&
            CanActivateDirect(entry, now_ms)) {
            entry.direct_eligible = true;
            entry.active_direct = true;
            entry.freeze_until_ms = now_ms + kPeerDirectRouteFreezeMs;
            EnterState(&entry, PeerRouteState::DirectActive, now_ms);
        }

        if ((entry.state == PeerRouteState::OfferReceived || entry.state == PeerRouteState::Probing) &&
            entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
            (now_ms - entry.last_observed_ms) >= offer_timeout_ms) {
            EnterCooldown(&entry, now_ms);
        } else if (entry.state == PeerRouteState::DirectActive &&
                   entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
                   (now_ms - entry.last_observed_ms) >= direct_ready_timeout_ms) {
            EnterCooldown(&entry, now_ms);
        } else if (entry.state == PeerRouteState::Cooldown) {
            uint64_t retry_after_ms = entry.retry_after_ms;
            if (retry_after_ms == 0 && entry.last_state_change_ms != 0) {
                retry_after_ms = entry.last_state_change_ms + cooldown_timeout_ms;
            }
            if (retry_after_ms != 0 && now_ms >= retry_after_ms) {
                entry.retry_after_ms = 0;
                EnterState(&entry, PeerRouteState::RelayOnly, now_ms);
            }
        }

        if (entry.state != previous_state) {
            PeerRouteStatus status;
            FillStatus(it->first, entry, &status);
            changed.push_back(status);
        }
    }
    return changed;
}

bool PeerLinkManager::CanRouteDirect(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    return it != peers_.end() &&
           it->second.active_direct &&
           HasEndpoint(it->second);
}

bool PeerLinkManager::TryGetDirectRoute(const std::string& peer_virtual_ip,
                                        uint64_t now_ms,
                                        uint64_t direct_data_timeout_ms,
                                        uint64_t direct_probe_grace_ms,
                                        PeerRouteStatus* out_status) const {
    (void)now_ms;
    (void)direct_data_timeout_ms;
    (void)direct_probe_grace_ms;

    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end() ||
        !it->second.direct_ready ||
        it->second.state == PeerRouteState::Cooldown ||
        !HasEndpoint(it->second)) {
        return false;
    }

    FillStatus(it->first, it->second, out_status);
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
        if (it->second.state == PeerRouteState::RelayOnly ||
            it->second.state == PeerRouteState::Cooldown ||
            !HasEndpoint(it->second) ||
            it->second.endpoint_family != endpoint_family ||
            it->second.endpoint_port != endpoint_port ||
            memcmp(it->second.endpoint_addr, endpoint_addr, sizeof(it->second.endpoint_addr)) != 0) {
            continue;
        }

        FillStatus(it->first, it->second, out_status);
        return true;
    }

    return false;
}

std::vector<PeerRouteStatus> PeerLinkManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerRouteStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        PeerRouteStatus status;
        FillStatus(it->first, it->second, &status);
        snapshot.push_back(status);
    }
    return snapshot;
}
