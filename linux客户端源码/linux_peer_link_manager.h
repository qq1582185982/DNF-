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
    DirectReady = 3,
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
    uint64_t last_observed_ms;
    uint64_t last_direct_data_ms;
    uint64_t last_state_change_ms;
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
    void MarkPeerDirectReady(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    void MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
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
    bool TryResolveByEndpoint(uint8_t endpoint_family,
                              const uint8_t* endpoint_addr,
                              uint16_t endpoint_port,
                              LinuxPeerRouteStatus* out_status) const;
    std::vector<LinuxPeerRouteStatus> Snapshot() const;

private:
    struct Entry {
        Entry()
            : state(LinuxPeerRouteState::RelayOnly),
              endpoint_version(0),
              endpoint_family(0),
              endpoint_port(0),
              last_observed_ms(0),
              last_direct_data_ms(0),
              last_state_change_ms(0),
              pending_hello_version(0),
              pending_hello_nonce(0) {
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
        uint64_t pending_hello_version;
        uint32_t pending_hello_nonce;
    };

    mutable std::mutex mutex_;
    std::string local_virtual_ip_;
    std::map<std::string, Entry> peers_;
};
