#pragma once

#include <stdint.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

enum class PeerRouteState : uint8_t {
    RelayOnly = 0,
    OfferReceived = 1,
    Probing = 2,
    DirectReady = 3,
    Cooldown = 4
};

struct PeerRouteStatus {
    std::string peer_virtual_ip;
    PeerRouteState state;
    uint64_t endpoint_version;
    bool direct_ready;
    uint64_t last_observed_ms;
    uint64_t last_state_change_ms;
};

class PeerLinkManager {
public:
    PeerLinkManager();

    void SetLocalVirtualIp(const std::string& virtual_ip);
    void ResetAll();

    void UpdatePeerOffer(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void ObservePeerFrame(const std::string& peer_virtual_ip,
                          uint64_t endpoint_version,
                          PeerRouteState state);
    void MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    void MarkPeerDirectReady(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    void MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);

    bool CanRouteDirect(const std::string& peer_virtual_ip) const;
    std::vector<PeerRouteStatus> Snapshot() const;

private:
    struct Entry {
        Entry()
            : state(PeerRouteState::RelayOnly),
              endpoint_version(0),
              last_observed_ms(0),
              last_state_change_ms(0) {}

        PeerRouteState state;
        uint64_t endpoint_version;
        uint64_t last_observed_ms;
        uint64_t last_state_change_ms;
    };

    mutable std::mutex mutex_;
    std::string local_virtual_ip_;
    std::map<std::string, Entry> peers_;
};
