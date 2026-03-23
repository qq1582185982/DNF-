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
};

class PeerLinkManager {
public:
    PeerLinkManager();

    void SetLocalVirtualIp(const std::string& virtual_ip);
    void ResetAll();

    void UpdatePeerOffer(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void MarkPeerProbing(const std::string& peer_virtual_ip);
    void MarkPeerDirectReady(const std::string& peer_virtual_ip);
    void MarkPeerCooldown(const std::string& peer_virtual_ip);

    bool CanRouteDirect(const std::string& peer_virtual_ip) const;
    std::vector<PeerRouteStatus> Snapshot() const;

private:
    struct Entry {
        Entry()
            : state(PeerRouteState::RelayOnly),
              endpoint_version(0) {}

        PeerRouteState state;
        uint64_t endpoint_version;
    };

    mutable std::mutex mutex_;
    std::string local_virtual_ip_;
    std::map<std::string, Entry> peers_;
};
