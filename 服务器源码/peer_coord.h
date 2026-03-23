#pragma once

#include <stdint.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

enum class PeerEndpointState : uint8_t {
    Unknown = 0,
    RelayOnly = 1,
    OfferPending = 2,
    Active = 3
};

struct PeerCoordStatus {
    std::string peer_virtual_ip;
    uint64_t endpoint_version;
    PeerEndpointState state;
};

class PeerCoord {
public:
    PeerCoord();

    void Reset();
    uint64_t BumpEndpointVersion(const std::string& peer_virtual_ip);
    void ObservePeerFrame(const std::string& peer_virtual_ip,
                          uint64_t endpoint_version,
                          PeerEndpointState state);
    void SetState(const std::string& peer_virtual_ip, PeerEndpointState state);
    uint64_t GetEndpointVersion(const std::string& peer_virtual_ip) const;
    std::vector<PeerCoordStatus> Snapshot() const;

private:
    struct Entry {
        Entry()
            : endpoint_version(0),
              state(PeerEndpointState::Unknown) {}

        uint64_t endpoint_version;
        PeerEndpointState state;
    };

    mutable std::mutex mutex_;
    std::map<std::string, Entry> peers_;
};
