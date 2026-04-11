#pragma once

#include <stdint.h>

#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

enum class LinuxPeerRouteState : uint8_t {
    RelayOnly = 0,
    OfferReceived = 1,
    Probing = 2,
    DirectActive = 3,
    Cooldown = 4
};

struct LinuxPeerRouteStatus {
    std::string peer_virtual_ip;
    LinuxPeerRouteState state;
    uint64_t endpoint_version;
    uint8_t endpoint_family;
    uint16_t endpoint_port;
    uint8_t endpoint_addr[16];
    bool direct_ready;
    bool direct_eligible;
    bool active_direct;
    uint64_t last_observed_ms;
    uint64_t last_direct_data_ms;
    uint64_t last_state_change_ms;
    uint64_t acked_at_ms;
    uint64_t first_direct_data_ms;
    uint64_t last_direct_failure_ms;
    uint64_t freeze_until_ms;
    uint64_t retry_after_ms;
    uint32_t direct_sample_count;
    uint32_t probe_failures;
    uint32_t active_failures;
};

class LinuxPeerLinkManager {
public:
    LinuxPeerLinkManager();

    void SetLocalVirtualIp(const std::string& virtual_ip);
    void ResetAll();

    bool UpdatePeerOffer(const std::string& peer_virtual_ip,
                         uint64_t endpoint_version,
                         uint8_t endpoint_family,
                         const uint8_t* endpoint_addr,
                         uint16_t endpoint_port);
    bool ObserveDirectEndpoint(const std::string& peer_virtual_ip,
                               uint8_t endpoint_family,
                               const uint8_t* endpoint_addr,
                               uint16_t endpoint_port,
                               bool* endpoint_changed = NULL,
                               LinuxPeerRouteStatus* out_status = NULL);
    void TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void TouchPeerDirectData(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void ObservePeerFrame(const std::string& peer_virtual_ip,
                          uint64_t endpoint_version,
                          LinuxPeerRouteState state);
    void RecordPeerHelloSent(const std::string& peer_virtual_ip,
                             uint64_t endpoint_version,
                             uint32_t nonce);
    bool TryPromotePeerDirectReady(const std::string& peer_virtual_ip,
                                   uint64_t endpoint_version,
                                   uint32_t nonce);
    void MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    void MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    bool RecordDirectSendFailure(const std::string& peer_virtual_ip,
                                 uint64_t endpoint_version,
                                 bool active_path,
                                 LinuxPeerRouteStatus* out_status = NULL);
    std::vector<LinuxPeerRouteStatus> ExpireStalePeers(uint64_t now_ms,
                                                       uint64_t offer_timeout_ms,
                                                       uint64_t direct_ready_timeout_ms,
                                                       uint64_t cooldown_timeout_ms);

    bool CanRouteDirect(const std::string& peer_virtual_ip) const;
    bool TryGetDirectRoute(const std::string& peer_virtual_ip,
                           uint64_t now_ms,
                           uint64_t direct_data_timeout_ms,
                           uint64_t direct_probe_grace_ms,
                           LinuxPeerRouteStatus* out_status) const;
    bool TryResolveUniquePeerByAddress(uint8_t endpoint_family,
                                       const uint8_t* endpoint_addr,
                                       LinuxPeerRouteStatus* out_status) const;
    bool TryResolveByEndpoint(uint8_t endpoint_family,
                              const uint8_t* endpoint_addr,
                              uint16_t endpoint_port,
                              LinuxPeerRouteStatus* out_status) const;
    std::vector<LinuxPeerRouteStatus> Snapshot() const;

private:
    struct Candidate {
        uint8_t endpoint_family;
        uint16_t endpoint_port;
        uint8_t endpoint_addr[16];
        uint32_t failure_count;

        Candidate()
            : endpoint_family(0),
              endpoint_port(0),
              failure_count(0) {
            memset(endpoint_addr, 0, sizeof(endpoint_addr));
        }
    };

    struct Entry {
        Entry()
            : state(LinuxPeerRouteState::RelayOnly),
              endpoint_version(0),
              endpoint_family(0),
              endpoint_port(0),
              last_observed_ms(0),
              last_direct_data_ms(0),
              last_state_change_ms(0),
              acked_at_ms(0),
              first_direct_data_ms(0),
              last_direct_failure_ms(0),
              freeze_until_ms(0),
              retry_after_ms(0),
              direct_sample_count(0),
              probe_failures(0),
              active_failures(0),
              direct_ready(false),
              direct_eligible(false),
              active_direct(false),
              selected_candidate_index(0),
              pending_hello_version(0) {
            memset(endpoint_addr, 0, sizeof(endpoint_addr));
        }

        LinuxPeerRouteState state;
        uint64_t endpoint_version;
        uint8_t endpoint_family;
        uint16_t endpoint_port;
        uint8_t endpoint_addr[16];
        uint64_t last_observed_ms;
        uint64_t last_direct_data_ms;
        uint64_t last_state_change_ms;
        uint64_t acked_at_ms;
        uint64_t first_direct_data_ms;
        uint64_t last_direct_failure_ms;
        uint64_t freeze_until_ms;
        uint64_t retry_after_ms;
        uint32_t direct_sample_count;
        uint32_t probe_failures;
        uint32_t active_failures;
        bool direct_ready;
        bool direct_eligible;
        bool active_direct;
        std::vector<Candidate> candidates;
        size_t selected_candidate_index;
        uint64_t pending_hello_version;
        std::vector<uint32_t> pending_hello_nonces;
    };

    mutable std::mutex mutex_;
    std::string local_virtual_ip_;
    std::map<std::string, Entry> peers_;

    static bool HasEndpoint(const Entry& entry);
    static bool CanActivateDirect(const Entry& entry, uint64_t now_ms);
    static void ResetPendingHello(Entry* entry);
    static void ResetDirectAssessment(Entry* entry);
    static void EnterState(Entry* entry, LinuxPeerRouteState next_state, uint64_t now_ms);
    static void EnterCooldown(Entry* entry, uint64_t now_ms);
    static bool SameCandidate(const Candidate& candidate,
                              uint8_t endpoint_family,
                              const uint8_t* endpoint_addr,
                              uint16_t endpoint_port);
    static bool AddCandidate(Entry* entry,
                             uint8_t endpoint_family,
                             const uint8_t* endpoint_addr,
                             uint16_t endpoint_port,
                             size_t* out_index = NULL);
    static bool SelectCandidate(Entry* entry, size_t index);
    static bool SelectNextCandidate(Entry* entry);
    static void FillStatus(const std::string& peer_virtual_ip,
                           const Entry& entry,
                           LinuxPeerRouteStatus* out_status);
};
