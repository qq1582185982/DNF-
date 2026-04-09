#include "linux_peer_link_manager.h"

#include <chrono>
#include <cstring>

namespace {

const uint64_t kPeerDirectEligibilityStableMs = 3000;
const uint32_t kPeerDirectEligibilitySamples = 3;
const uint64_t kPeerDirectSampleResetMs = 8000;
const uint64_t kPeerDirectActivationFreshMs = 5000;
const uint32_t kPeerDirectProbeFailureThreshold = 6;
const uint32_t kPeerDirectActiveFailureThreshold = 3;
const uint64_t kPeerDirectRouteFreezeMs = 30000;
const uint64_t kPeerDirectCooldownHoldMs = 30000;

uint64_t linux_peer_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}

LinuxPeerLinkManager::LinuxPeerLinkManager() {
}

bool LinuxPeerLinkManager::HasEndpoint(const Entry& entry) {
    return entry.endpoint_family != 0 && entry.endpoint_port != 0;
}

bool LinuxPeerLinkManager::CanActivateDirect(const Entry& entry, uint64_t now_ms) {
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

void LinuxPeerLinkManager::ResetPendingHello(Entry* entry) {
    if (entry == NULL) {
        return;
    }
    entry->pending_hello_version = 0;
    entry->pending_hello_nonce = 0;
}

void LinuxPeerLinkManager::ResetDirectAssessment(Entry* entry) {
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

void LinuxPeerLinkManager::EnterState(Entry* entry, LinuxPeerRouteState next_state, uint64_t now_ms) {
    if (entry == NULL) {
        return;
    }
    if (entry->state != next_state) {
        entry->state = next_state;
        entry->last_state_change_ms = now_ms;
    }
}

void LinuxPeerLinkManager::EnterCooldown(Entry* entry, uint64_t now_ms) {
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
    EnterState(entry, LinuxPeerRouteState::Cooldown, now_ms);
}

void LinuxPeerLinkManager::FillStatus(const std::string& peer_virtual_ip,
                                      const Entry& entry,
                                      LinuxPeerRouteStatus* out_status) {
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

    if (same_version) {
        if (entry.state == LinuxPeerRouteState::Cooldown &&
            entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
            return false;
        }
        if ((entry.state == LinuxPeerRouteState::Probing &&
             entry.pending_hello_version == endpoint_version &&
             entry.pending_hello_nonce != 0) ||
            entry.direct_ready ||
            entry.active_direct) {
            return false;
        }
        if (same_endpoint) {
            const bool should_retry_stable_offer =
                entry.pending_hello_nonce == 0 &&
                !entry.direct_ready &&
                !entry.active_direct &&
                (entry.state == LinuxPeerRouteState::RelayOnly ||
                 entry.state == LinuxPeerRouteState::Cooldown);
            if (!should_retry_stable_offer) {
                return false;
            }
        }
    }

    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.endpoint_family = endpoint_family;
    entry.endpoint_port = endpoint_port;
    memcpy(entry.endpoint_addr, normalized_addr, sizeof(entry.endpoint_addr));

    if (entry.state == LinuxPeerRouteState::Cooldown &&
        entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
        return false;
    }

    ResetDirectAssessment(&entry);
    entry.retry_after_ms = 0;
    EnterState(&entry, LinuxPeerRouteState::OfferReceived, now);
    return true;
}

bool LinuxPeerLinkManager::ObserveDirectEndpoint(const std::string& peer_virtual_ip,
                                                 uint8_t endpoint_family,
                                                 const uint8_t* endpoint_addr,
                                                 uint16_t endpoint_port,
                                                 bool* endpoint_changed,
                                                 LinuxPeerRouteStatus* out_status) {
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

    const uint64_t now = linux_peer_now_ms();
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
            entry.state != LinuxPeerRouteState::DirectActive &&
            entry.state != LinuxPeerRouteState::Cooldown) {
            EnterState(&entry, LinuxPeerRouteState::Probing, now);
        }
    }

    FillStatus(it->first, entry, out_status);
    if (endpoint_changed != NULL) {
        *endpoint_changed = changed;
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
    const uint64_t previous_direct_data_ms = entry.last_direct_data_ms;
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;
    entry.probe_failures = 0;
    entry.active_failures = 0;

    if (!entry.direct_ready || entry.state == LinuxPeerRouteState::Cooldown ||
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
        EnterState(&entry, LinuxPeerRouteState::DirectActive, now);
    }
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

    if (state == LinuxPeerRouteState::Cooldown) {
        EnterCooldown(&entry, now);
        return;
    }

    if (state == LinuxPeerRouteState::Probing) {
        if (entry.state != LinuxPeerRouteState::DirectActive) {
            EnterState(&entry, LinuxPeerRouteState::Probing, now);
        }
        return;
    }

    EnterState(&entry, state, now);
    if (state != LinuxPeerRouteState::Probing) {
        ResetPendingHello(&entry);
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

    if (entry.state == LinuxPeerRouteState::Cooldown &&
        entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
        return;
    }

    ResetDirectAssessment(&entry);
    entry.retry_after_ms = 0;
    entry.pending_hello_version = entry.endpoint_version;
    entry.pending_hello_nonce = nonce;
    EnterState(&entry, LinuxPeerRouteState::Probing, now);
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
    EnterState(&entry, LinuxPeerRouteState::Probing, now);
    return entry.direct_ready;
}

void LinuxPeerLinkManager::MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    const uint64_t now = linux_peer_now_ms();
    const uint64_t previous_version = entry.endpoint_version;
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = now;

    if (entry.state == LinuxPeerRouteState::Cooldown &&
        entry.retry_after_ms != 0 && now < entry.retry_after_ms) {
        return;
    }

    if (entry.state == LinuxPeerRouteState::DirectActive && endpoint_version > previous_version) {
        ResetDirectAssessment(&entry);
        entry.retry_after_ms = 0;
        EnterState(&entry, LinuxPeerRouteState::Probing, now);
        return;
    }

    if (entry.state != LinuxPeerRouteState::DirectActive) {
        EnterState(&entry, LinuxPeerRouteState::Probing, now);
    }
}

void LinuxPeerLinkManager::MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    Entry& entry = peers_[peer_virtual_ip];
    if (endpoint_version > entry.endpoint_version) {
        entry.endpoint_version = endpoint_version;
    }
    entry.last_observed_ms = linux_peer_now_ms();
    EnterCooldown(&entry, entry.last_observed_ms);
}

bool LinuxPeerLinkManager::RecordDirectSendFailure(const std::string& peer_virtual_ip,
                                                   uint64_t endpoint_version,
                                                   bool active_path,
                                                   LinuxPeerRouteStatus* out_status) {
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
    entry.last_direct_failure_ms = now;

    const LinuxPeerRouteState previous_state = entry.state;
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
            EnterState(&entry, LinuxPeerRouteState::Probing, now);
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
        } else if (entry.state != LinuxPeerRouteState::Cooldown) {
            EnterState(&entry, LinuxPeerRouteState::Probing, now);
        }
    }

    FillStatus(it->first, entry, out_status);
    return entry.state != previous_state;
}

std::vector<LinuxPeerRouteStatus> LinuxPeerLinkManager::ExpireStalePeers(uint64_t now_ms,
                                                                         uint64_t offer_timeout_ms,
                                                                         uint64_t direct_ready_timeout_ms,
                                                                         uint64_t cooldown_timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LinuxPeerRouteStatus> changed;
    for (std::map<std::string, Entry>::iterator it = peers_.begin(); it != peers_.end(); ++it) {
        Entry& entry = it->second;
        const LinuxPeerRouteState previous_state = entry.state;

        if (!entry.active_direct &&
            entry.state == LinuxPeerRouteState::Probing &&
            entry.last_direct_data_ms != 0 &&
            now_ms >= entry.last_direct_data_ms &&
            (now_ms - entry.last_direct_data_ms) <= kPeerDirectActivationFreshMs &&
            CanActivateDirect(entry, now_ms)) {
            entry.direct_eligible = true;
            entry.active_direct = true;
            entry.freeze_until_ms = now_ms + kPeerDirectRouteFreezeMs;
            EnterState(&entry, LinuxPeerRouteState::DirectActive, now_ms);
        }

        if ((entry.state == LinuxPeerRouteState::OfferReceived || entry.state == LinuxPeerRouteState::Probing) &&
            entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
            (now_ms - entry.last_observed_ms) >= offer_timeout_ms) {
            EnterCooldown(&entry, now_ms);
        } else if (entry.state == LinuxPeerRouteState::DirectActive &&
                   entry.last_observed_ms != 0 && now_ms > entry.last_observed_ms &&
                   (now_ms - entry.last_observed_ms) >= direct_ready_timeout_ms) {
            EnterCooldown(&entry, now_ms);
        } else if (entry.state == LinuxPeerRouteState::Cooldown) {
            uint64_t retry_after_ms = entry.retry_after_ms;
            if (retry_after_ms == 0 && entry.last_state_change_ms != 0) {
                retry_after_ms = entry.last_state_change_ms + cooldown_timeout_ms;
            }
            if (retry_after_ms != 0 && now_ms >= retry_after_ms) {
                entry.retry_after_ms = 0;
                EnterState(&entry, LinuxPeerRouteState::RelayOnly, now_ms);
            }
        }

        if (entry.state != previous_state) {
            LinuxPeerRouteStatus status;
            FillStatus(it->first, entry, &status);
            changed.push_back(status);
        }
    }
    return changed;
}

bool LinuxPeerLinkManager::CanRouteDirect(const std::string& peer_virtual_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    return it != peers_.end() &&
           it->second.active_direct &&
           HasEndpoint(it->second);
}

bool LinuxPeerLinkManager::TryGetDirectRoute(const std::string& peer_virtual_ip,
                                             uint64_t now_ms,
                                             uint64_t direct_data_timeout_ms,
                                             uint64_t direct_probe_grace_ms,
                                             LinuxPeerRouteStatus* out_status) const {
    (void)now_ms;
    (void)direct_data_timeout_ms;
    (void)direct_probe_grace_ms;

    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, Entry>::const_iterator it = peers_.find(peer_virtual_ip);
    if (it == peers_.end() ||
        !it->second.direct_ready ||
        it->second.state == LinuxPeerRouteState::Cooldown ||
        !HasEndpoint(it->second)) {
        return false;
    }

    FillStatus(it->first, it->second, out_status);
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
        if (it->second.state == LinuxPeerRouteState::Cooldown ||
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

std::vector<LinuxPeerRouteStatus> LinuxPeerLinkManager::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LinuxPeerRouteStatus> snapshot;
    for (std::map<std::string, Entry>::const_iterator it = peers_.begin(); it != peers_.end(); ++it) {
        LinuxPeerRouteStatus status;
        FillStatus(it->first, it->second, &status);
        snapshot.push_back(status);
    }
    return snapshot;
}
