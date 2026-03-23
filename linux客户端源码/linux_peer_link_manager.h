#pragma once

#include <stdint.h>

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
    bool direct_ready;
    uint64_t last_observed_ms;
    uint64_t last_state_change_ms;
};

class LinuxPeerLinkManager {
public:
    LinuxPeerLinkManager();

    void SetLocalVirtualIp(const std::string& virtual_ip);
    void ResetAll();

    void UpdatePeerOffer(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void TouchPeer(const std::string& peer_virtual_ip, uint64_t endpoint_version);
    void ObservePeerFrame(const std::string& peer_virtual_ip,
                          uint64_t endpoint_version,
                          LinuxPeerRouteState state);
    void MarkPeerProbing(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    void MarkPeerDirectReady(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);
    void MarkPeerCooldown(const std::string& peer_virtual_ip, uint64_t endpoint_version = 0);

    bool CanRouteDirect(const std::string& peer_virtual_ip) const;
    std::vector<LinuxPeerRouteStatus> Snapshot() const;

private:
    struct Entry {
        Entry()
            : state(LinuxPeerRouteState::RelayOnly),
              endpoint_version(0),
              last_observed_ms(0),
              last_state_change_ms(0) {}

        LinuxPeerRouteState state;
        uint64_t endpoint_version;
        uint64_t last_observed_ms;
        uint64_t last_state_change_ms;
    };

    mutable std::mutex mutex_;
    std::string local_virtual_ip_;
    std::map<std::string, Entry> peers_;
};
