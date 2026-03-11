#include "ip_pool_manager.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace {

std::vector<std::string> Split(const std::string& input, char delim) {
    std::vector<std::string> result;
    std::stringstream stream(input);
    std::string item;
    while (std::getline(stream, item, delim)) {
        result.push_back(item);
    }
    return result;
}

}  // namespace

IPPoolManager::IPPoolManager() {}

bool IPPoolManager::ConfigurePool(const PoolConfig& config, std::string* error) {
    if (config.pool_key.empty()) {
        if (error) *error = "pool_key is required";
        return false;
    }

    PoolState pool;
    pool.config = config;

    if (!PreparePool(&pool, error)) {
        return false;
    }

    pools_[config.pool_key] = pool;
    return true;
}

bool IPPoolManager::AcquireLease(const std::string& pool_key, const ip_tunnel::LeaseRequest& request, LeaseRecord* out_record, std::string* error) {
    std::map<std::string, PoolState>::iterator it = pools_.find(pool_key);
    if (it == pools_.end()) {
        if (error) *error = "server pool not found";
        return false;
    }

    PoolState* pool = &it->second;
    const uint64_t now_ms = NowMs();

    CleanupExpired(now_ms);

    std::map<std::string, LeaseState>::iterator active_it = pool->by_session.find(request.session_uuid);
    if (active_it != pool->by_session.end()) {
        TouchLease(&active_it->second, pool->config.lease_seconds, now_ms);
        if (out_record) {
            *out_record = active_it->second.record;
        }
        return true;
    }

    if (TryReuseStickyLease(pool, request, now_ms, out_record)) {
        return true;
    }

    if (!request.preferred_ip.empty()) {
        uint32_t preferred_ip = 0;
        if (!ParseIPv4(request.preferred_ip, &preferred_ip)) {
            if (error) *error = "preferred_ip is invalid";
            return false;
        }
        if (TryAcquireSpecificIP(pool, request, preferred_ip, now_ms, out_record, error)) {
            return true;
        }
    }

    return TryAcquireNextFreeIP(pool, request, now_ms, out_record, error);
}

bool IPPoolManager::GetLease(const std::string& pool_key, const std::string& session_uuid, LeaseRecord* out_record, std::string* error) {
    CleanupExpired(NowMs());

    std::map<std::string, PoolState>::iterator it = pools_.find(pool_key);
    if (it == pools_.end()) {
        if (error) *error = "server pool not found";
        return false;
    }

    PoolState* pool = &it->second;
    std::map<std::string, LeaseState>::iterator lease_it = pool->by_session.find(session_uuid);
    if (lease_it == pool->by_session.end()) {
        if (error) *error = "lease not found";
        return false;
    }

    if (out_record) {
        *out_record = lease_it->second.record;
    }
    return true;
}

bool IPPoolManager::RenewLease(const std::string& pool_key, const std::string& session_uuid, LeaseRecord* out_record, std::string* error) {
    CleanupExpired(NowMs());

    std::map<std::string, PoolState>::iterator it = pools_.find(pool_key);
    if (it == pools_.end()) {
        if (error) *error = "server pool not found";
        return false;
    }

    PoolState* pool = &it->second;
    std::map<std::string, LeaseState>::iterator lease_it = pool->by_session.find(session_uuid);
    if (lease_it == pool->by_session.end()) {
        if (error) *error = "lease not found";
        return false;
    }

    TouchLease(&lease_it->second, pool->config.lease_seconds, NowMs());
    if (out_record) {
        *out_record = lease_it->second.record;
    }
    return true;
}

bool IPPoolManager::ReleaseLease(const std::string& pool_key, const std::string& session_uuid) {
    CleanupExpired(NowMs());

    std::map<std::string, PoolState>::iterator it = pools_.find(pool_key);
    if (it == pools_.end()) {
        return false;
    }

    PoolState* pool = &it->second;
    std::map<std::string, LeaseState>::iterator lease_it = pool->by_session.find(session_uuid);
    if (lease_it == pool->by_session.end()) {
        return false;
    }

    uint32_t ip = 0;
    ParseIPv4(lease_it->second.record.virtual_ip, &ip);
    pool->by_ip.erase(ip);
    pool->released_sessions[session_uuid] = lease_it->second;
    pool->released_sessions[session_uuid].released_at_ms = NowMs();
    pool->by_session.erase(lease_it);
    if (pool->requestable_reserved_ips.count(ip) == 0 &&
        pool->reserved_ips.count(ip) == 0) {
        pool->available_ips.push_back(ip);
    }
    return true;
}

size_t IPPoolManager::CleanupExpired(uint64_t now_ms) {
    size_t cleaned = 0;
    for (std::map<std::string, PoolState>::iterator pool_it = pools_.begin(); pool_it != pools_.end(); ++pool_it) {
        PoolState* pool = &pool_it->second;

        std::vector<std::string> expired_sessions;
        for (std::map<std::string, LeaseState>::const_iterator it = pool->by_session.begin();
             it != pool->by_session.end(); ++it) {
            if (it->second.record.expires_at_ms <= now_ms) {
                expired_sessions.push_back(it->first);
            }
        }

        for (size_t i = 0; i < expired_sessions.size(); ++i) {
            const std::string& session_uuid = expired_sessions[i];
            std::map<std::string, LeaseState>::iterator lease_it = pool->by_session.find(session_uuid);
            if (lease_it == pool->by_session.end()) {
                continue;
            }

            uint32_t ip = 0;
            ParseIPv4(lease_it->second.record.virtual_ip, &ip);
            pool->by_ip.erase(ip);
            pool->released_sessions[session_uuid] = lease_it->second;
            pool->released_sessions[session_uuid].released_at_ms = now_ms;
            pool->by_session.erase(lease_it);
            if (pool->requestable_reserved_ips.count(ip) == 0 &&
                pool->reserved_ips.count(ip) == 0) {
                pool->available_ips.push_back(ip);
            }
            ++cleaned;
        }

        std::vector<std::string> stale_released;
        for (std::map<std::string, LeaseState>::const_iterator it = pool->released_sessions.begin();
             it != pool->released_sessions.end(); ++it) {
            if (it->second.released_at_ms + pool->config.sticky_seconds * 1000ULL <= now_ms) {
                stale_released.push_back(it->first);
            }
        }

        for (size_t i = 0; i < stale_released.size(); ++i) {
            pool->released_sessions.erase(stale_released[i]);
        }
    }

    return cleaned;
}

std::vector<IPPoolManager::LeaseRecord> IPPoolManager::Snapshot(const std::string& pool_key) const {
    std::vector<LeaseRecord> snapshot;
    std::map<std::string, PoolState>::const_iterator it = pools_.find(pool_key);
    if (it == pools_.end()) {
        return snapshot;
    }

    for (std::map<std::string, LeaseState>::const_iterator lease_it = it->second.by_session.begin();
         lease_it != it->second.by_session.end(); ++lease_it) {
        snapshot.push_back(lease_it->second.record);
    }
    return snapshot;
}

uint64_t IPPoolManager::NowMs() {
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

bool IPPoolManager::ParseIPv4(const std::string& text, uint32_t* out_ip) {
    std::vector<std::string> parts = Split(text, '.');
    if (parts.size() != 4) {
        return false;
    }

    uint32_t value = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        std::stringstream ss(parts[i]);
        int octet = -1;
        ss >> octet;
        if (ss.fail() || !ss.eof() || octet < 0 || octet > 255) {
            return false;
        }
        value = (value << 8) | (uint32_t)octet;
    }

    if (out_ip) {
        *out_ip = value;
    }
    return true;
}

std::string IPPoolManager::IPv4ToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 24) & 0xFF) << '.'
       << ((ip >> 16) & 0xFF) << '.'
       << ((ip >> 8) & 0xFF) << '.'
       << (ip & 0xFF);
    return ss.str();
}

bool IPPoolManager::ParseCIDR(const std::string& cidr, uint32_t* out_network, uint32_t* out_mask) {
    std::vector<std::string> parts = Split(cidr, '/');
    if (parts.size() != 2) {
        return false;
    }

    uint32_t network = 0;
    if (!ParseIPv4(parts[0], &network)) {
        return false;
    }

    std::stringstream ss(parts[1]);
    int prefix_bits = -1;
    ss >> prefix_bits;
    if (ss.fail() || !ss.eof() || prefix_bits < 0 || prefix_bits > 32) {
        return false;
    }

    uint32_t mask = PrefixToMask((uint32_t)prefix_bits);
    network &= mask;

    if (out_network) {
        *out_network = network;
    }
    if (out_mask) {
        *out_mask = mask;
    }
    return true;
}

uint32_t IPPoolManager::PrefixToMask(uint32_t prefix_bits) {
    if (prefix_bits == 0) {
        return 0;
    }
    if (prefix_bits >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32 - prefix_bits);
}

uint32_t IPPoolManager::HostCount(uint32_t mask) {
    return (~mask) + 1;
}

bool IPPoolManager::PreparePool(PoolState* pool, std::string* error) {
    if (!ParseCIDR(pool->config.cidr, &pool->network_ip, &pool->subnet_mask)) {
        if (error) *error = "invalid CIDR";
        return false;
    }

    const uint32_t host_count = HostCount(pool->subnet_mask);
    if (host_count < 8) {
        if (error) *error = "CIDR is too small for a client pool";
        return false;
    }

    pool->broadcast_ip = pool->network_ip + host_count - 1;

    if (!pool->config.gateway_ip.empty()) {
        if (!ParseIPv4(pool->config.gateway_ip, &pool->gateway_ip)) {
            if (error) *error = "invalid gateway_ip";
            return false;
        }
    } else {
        pool->gateway_ip = pool->network_ip + 1;
        pool->config.gateway_ip = IPv4ToString(pool->gateway_ip);
    }

    if (!pool->config.server_virtual_ip.empty()) {
        if (!ParseIPv4(pool->config.server_virtual_ip, &pool->server_virtual_ip)) {
            if (error) *error = "invalid server_virtual_ip";
            return false;
        }
    }

    if (pool->server_virtual_ip != 0) {
        if (pool->server_virtual_ip <= pool->network_ip || pool->server_virtual_ip >= pool->broadcast_ip) {
            if (error) *error = "server_virtual_ip is outside pool CIDR";
            return false;
        }
        if (pool->server_virtual_ip == pool->gateway_ip) {
            if (error) *error = "server_virtual_ip conflicts with gateway_ip";
            return false;
        }
    }

    pool->reserved_ips.insert(pool->network_ip);
    pool->reserved_ips.insert(pool->broadcast_ip);
    pool->reserved_ips.insert(pool->gateway_ip);
    if (pool->server_virtual_ip != 0) {
        pool->reserved_ips.insert(pool->server_virtual_ip);
    }

    for (size_t i = 0; i < pool->config.additional_reserved_ips.size(); ++i) {
        uint32_t reserved_ip = 0;
        if (!ParseIPv4(pool->config.additional_reserved_ips[i], &reserved_ip)) {
            if (error) *error = "invalid additional_reserved_ip";
            return false;
        }
        if (reserved_ip <= pool->network_ip || reserved_ip >= pool->broadcast_ip) {
            if (error) *error = "additional_reserved_ip is outside pool CIDR";
            return false;
        }
        if (reserved_ip == pool->gateway_ip) {
            if (error) *error = "additional_reserved_ip conflicts with gateway_ip";
            return false;
        }
        if (pool->server_virtual_ip != 0 && reserved_ip == pool->server_virtual_ip) {
            if (error) *error = "additional_reserved_ip conflicts with server_virtual_ip";
            return false;
        }
        pool->reserved_ips.insert(reserved_ip);
        pool->requestable_reserved_ips.insert(reserved_ip);
    }

    const uint32_t first_usable = pool->network_ip + std::max<uint32_t>(2, pool->config.first_host_offset);
    for (uint32_t ip = first_usable; ip < pool->broadcast_ip; ++ip) {
        if (pool->reserved_ips.count(ip) != 0) {
            continue;
        }
        pool->available_ips.push_back(ip);
    }

    if (pool->available_ips.empty()) {
        if (error) *error = "no usable IPs in pool";
        return false;
    }

    return true;
}

bool IPPoolManager::TryReuseStickyLease(PoolState* pool, const ip_tunnel::LeaseRequest& request, uint64_t now_ms, LeaseRecord* out_record) {
    std::map<std::string, LeaseState>::iterator it = pool->released_sessions.find(request.session_uuid);
    if (it == pool->released_sessions.end()) {
        return false;
    }

    if (it->second.released_at_ms + pool->config.sticky_seconds * 1000ULL <= now_ms) {
        pool->released_sessions.erase(it);
        return false;
    }

    uint32_t ip = 0;
    if (!ParseIPv4(it->second.record.virtual_ip, &ip)) {
        pool->released_sessions.erase(it);
        return false;
    }

    if (pool->by_ip.count(ip) != 0) {
        pool->released_sessions.erase(it);
        return false;
    }

    std::vector<uint32_t>::iterator avail_it = std::find(pool->available_ips.begin(), pool->available_ips.end(), ip);
    if (avail_it != pool->available_ips.end()) {
        pool->available_ips.erase(avail_it);
    }

    LeaseState state;
    state.record = BuildLeaseRecord(*pool, request, ip, now_ms, true);
    pool->by_session[request.session_uuid] = state;
    pool->by_ip[ip] = request.session_uuid;
    pool->released_sessions.erase(it);

    if (out_record) {
        *out_record = state.record;
    }
    return true;
}

bool IPPoolManager::TryAcquireSpecificIP(PoolState* pool, const ip_tunnel::LeaseRequest& request, uint32_t requested_ip, uint64_t now_ms, LeaseRecord* out_record, std::string* error) {
    if (requested_ip <= pool->network_ip || requested_ip >= pool->broadcast_ip) {
        if (error) *error = "preferred_ip is outside pool CIDR";
        return false;
    }

    if (pool->by_ip.count(requested_ip) != 0) {
        if (error) *error = "preferred_ip is already assigned";
        return false;
    }

    if (pool->reserved_ips.count(requested_ip) != 0) {
        if (pool->requestable_reserved_ips.count(requested_ip) == 0) {
            if (error) *error = "preferred_ip is reserved";
            return false;
        }

        LeaseState state;
        state.record = BuildLeaseRecord(*pool, request, requested_ip, now_ms, false);
        pool->by_session[request.session_uuid] = state;
        pool->by_ip[requested_ip] = request.session_uuid;

        if (out_record) {
            *out_record = state.record;
        }
        return true;
    }

    std::vector<uint32_t>::iterator it = std::find(pool->available_ips.begin(), pool->available_ips.end(), requested_ip);
    if (it == pool->available_ips.end()) {
        if (error) *error = "preferred_ip is not available";
        return false;
    }

    pool->available_ips.erase(it);
    LeaseState state;
    state.record = BuildLeaseRecord(*pool, request, requested_ip, now_ms, false);
    pool->by_session[request.session_uuid] = state;
    pool->by_ip[requested_ip] = request.session_uuid;

    if (out_record) {
        *out_record = state.record;
    }
    return true;
}

bool IPPoolManager::TryAcquireNextFreeIP(PoolState* pool, const ip_tunnel::LeaseRequest& request, uint64_t now_ms, LeaseRecord* out_record, std::string* error) {
    if (pool->available_ips.empty()) {
        if (error) *error = "ip pool exhausted";
        return false;
    }

    const uint32_t assigned_ip = pool->available_ips.front();
    pool->available_ips.erase(pool->available_ips.begin());

    LeaseState state;
    state.record = BuildLeaseRecord(*pool, request, assigned_ip, now_ms, false);
    pool->by_session[request.session_uuid] = state;
    pool->by_ip[assigned_ip] = request.session_uuid;

    if (out_record) {
        *out_record = state.record;
    }
    return true;
}

IPPoolManager::LeaseRecord IPPoolManager::BuildLeaseRecord(const PoolState& pool,
                                                           const ip_tunnel::LeaseRequest& request,
                                                           uint32_t assigned_ip,
                                                           uint64_t now_ms,
                                                           bool reused_previous_ip) const {
    LeaseRecord record;
    record.session_uuid = request.session_uuid;
    record.client_id = request.client_id;
    record.server_key = request.server_key;
    record.virtual_ip = IPv4ToString(assigned_ip);
    record.subnet_mask = IPv4ToString(pool.subnet_mask);
    record.gateway_ip = pool.config.gateway_ip;
    record.server_virtual_ip = pool.config.server_virtual_ip;
    record.lease_seconds = pool.config.lease_seconds;
    record.issued_at_ms = now_ms;
    record.expires_at_ms = now_ms + (uint64_t)pool.config.lease_seconds * 1000ULL;
    record.reused_previous_ip = reused_previous_ip;
    return record;
}

void IPPoolManager::TouchLease(LeaseState* state, uint32_t lease_seconds, uint64_t now_ms) {
    state->record.lease_seconds = lease_seconds;
    state->record.expires_at_ms = now_ms + (uint64_t)lease_seconds * 1000ULL;
}
