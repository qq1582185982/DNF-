#pragma once

#include "ip_lease_protocol.h"

#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <vector>

class IPPoolManager {
public:
    struct PoolConfig {
        std::string server_key;
        std::string cidr;
        std::string gateway_ip;
        uint32_t lease_seconds;
        uint32_t sticky_seconds;
        uint32_t first_host_offset;

        PoolConfig()
            : lease_seconds(ip_tunnel::kDefaultLeaseSeconds),
              sticky_seconds(300),
              first_host_offset(2) {}
    };

    struct LeaseRecord {
        std::string session_uuid;
        std::string client_id;
        std::string server_key;
        std::string virtual_ip;
        std::string subnet_mask;
        std::string gateway_ip;
        uint32_t lease_seconds;
        uint64_t issued_at_ms;
        uint64_t expires_at_ms;
        bool reused_previous_ip;

        LeaseRecord()
            : lease_seconds(ip_tunnel::kDefaultLeaseSeconds),
              issued_at_ms(0),
              expires_at_ms(0),
              reused_previous_ip(false) {}
    };

    IPPoolManager();

    bool ConfigurePool(const PoolConfig& config, std::string* error);
    bool AcquireLease(const ip_tunnel::LeaseRequest& request, LeaseRecord* out_record, std::string* error);
    bool RenewLease(const std::string& server_key, const std::string& session_uuid, LeaseRecord* out_record, std::string* error);
    bool ReleaseLease(const std::string& server_key, const std::string& session_uuid);
    size_t CleanupExpired(uint64_t now_ms);
    std::vector<LeaseRecord> Snapshot(const std::string& server_key) const;

private:
    struct LeaseState {
        LeaseRecord record;
        uint64_t released_at_ms;

        LeaseState() : released_at_ms(0) {}
    };

    struct PoolState {
        PoolConfig config;
        uint32_t network_ip;
        uint32_t subnet_mask;
        uint32_t broadcast_ip;
        uint32_t gateway_ip;
        std::vector<uint32_t> available_ips;
        std::map<std::string, LeaseState> by_session;
        std::map<uint32_t, std::string> by_ip;
        std::map<std::string, LeaseState> released_sessions;
        std::set<uint32_t> reserved_ips;

        PoolState()
            : network_ip(0),
              subnet_mask(0),
              broadcast_ip(0),
              gateway_ip(0) {}
    };

    static uint64_t NowMs();
    static bool ParseIPv4(const std::string& text, uint32_t* out_ip);
    static std::string IPv4ToString(uint32_t ip);
    static bool ParseCIDR(const std::string& cidr, uint32_t* out_network, uint32_t* out_mask);
    static uint32_t PrefixToMask(uint32_t prefix_bits);
    static uint32_t HostCount(uint32_t mask);

    bool PreparePool(PoolState* pool, std::string* error);
    bool TryReuseStickyLease(PoolState* pool, const ip_tunnel::LeaseRequest& request, uint64_t now_ms, LeaseRecord* out_record);
    bool TryAcquireSpecificIP(PoolState* pool, const ip_tunnel::LeaseRequest& request, uint32_t requested_ip, uint64_t now_ms, LeaseRecord* out_record, std::string* error);
    bool TryAcquireNextFreeIP(PoolState* pool, const ip_tunnel::LeaseRequest& request, uint64_t now_ms, LeaseRecord* out_record, std::string* error);
    LeaseRecord BuildLeaseRecord(const PoolState& pool, const ip_tunnel::LeaseRequest& request, uint32_t assigned_ip, uint64_t now_ms, bool reused_previous_ip) const;
    static void TouchLease(LeaseState* state, uint32_t lease_seconds, uint64_t now_ms);

    std::map<std::string, PoolState> pools_;
};
