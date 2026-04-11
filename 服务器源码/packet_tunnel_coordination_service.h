#ifndef PACKET_TUNNEL_COORDINATION_SERVICE_H_
#define PACKET_TUNNEL_COORDINATION_SERVICE_H_

#include "packet_tunnel_service_context.h"

#include <sstream>
#include <string>
#include <vector>

inline const char* PacketTunnelPeerEndpointStateName(PeerEndpointState state) {
    switch (state) {
    case PeerEndpointState::Unknown:
        return "未知";
    case PeerEndpointState::RelayOnly:
        return "仅中转";
    case PeerEndpointState::OfferPending:
        return "待提议";
    case PeerEndpointState::Active:
        return "已激活";
    default:
        return "未知";
    }
}

inline void PacketTunnelLogExpiredPeerCoordStates(PeerCoord* peer_coord,
                                                  const PacketTunnelServiceContext& context) {
    if (peer_coord == NULL) {
        return;
    }

    const uint64_t now_ms = monotonic_millis();
    std::vector<PeerCoordStatus> changed = peer_coord->ExpireStalePeers(now_ms,
                                                                        context.peer_offer_timeout_ms,
                                                                        context.peer_active_timeout_ms);
    for (size_t i = 0; i < changed.size(); ++i) {
        Logger::debug("[" + context.server_name + "|IP Tunnel] 对等端状态切换 " +
                      changed[i].peer_virtual_ip + " -> " +
                      PacketTunnelPeerEndpointStateName(changed[i].state) +
                      " 版本=" + std::to_string(changed[i].endpoint_version));
    }

    if (changed.empty()) {
        return;
    }

    std::ostringstream ss;
    std::vector<PeerCoordStatus> peers = peer_coord->Snapshot();
    for (size_t i = 0; i < peers.size(); ++i) {
        if (i != 0) {
            ss << "; ";
        }
        const uint64_t observed_age =
            (peers[i].last_observed_ms != 0 && now_ms > peers[i].last_observed_ms)
                ? (now_ms - peers[i].last_observed_ms)
                : 0;
        const uint64_t state_age =
            (peers[i].last_state_change_ms != 0 && now_ms > peers[i].last_state_change_ms)
                ? (now_ms - peers[i].last_state_change_ms)
                : 0;
        ss << peers[i].peer_virtual_ip
           << "[" << PacketTunnelPeerEndpointStateName(peers[i].state)
           << " 版本=" << peers[i].endpoint_version
           << " 观测=" << observed_age << "ms"
           << " 状态时长=" << state_age << "ms]";
    }
    Logger::debug("[" + context.server_name + "|IP Tunnel] 对等端快照 " +
                  (peers.empty() ? std::string("无") : ss.str()));
}

class CoordinationService {
public:
    explicit CoordinationService(const PacketTunnelServiceContext& context)
        : context_(context) {}

    void AnnouncePeerOffersForSession(const PacketTunnelServiceContext::SessionPtr& session,
                                      bool force_new_version) const {
        if (!session || !session->active || !session->use_udp) {
            return;
        }
        if (context_.is_peer_direct_excluded_session(session)) {
            Logger::debug("[" + context_.server_name +
                          "|IP Tunnel] 跳过对等端提议，当前会话被排除出直连: " +
                          context_.describe_scoped_session(session));
            return;
        }

        const std::string local_scope_key =
            context_.build_scoped_virtual_ip_key(session->server_key, session->virtual_ip_be);
        const std::string local_scope_label = context_.describe_scoped_session(session);
        if (!session->active) {
            return;
        }

        std::string session_lease_error;
        if (!context_.session_has_active_lease(session, &session_lease_error)) {
            Logger::debug("[" + context_.server_name +
                          "|IP Tunnel] 跳过对等端提议，会话没有有效租约: " +
                          local_scope_label + " 原因=" + session_lease_error);
            return;
        }

        PacketTunnelLogExpiredPeerCoordStates(context_.udp_peer_coord, context_);

        uint64_t local_version = context_.udp_peer_coord->GetEndpointVersion(local_scope_key);
        if (force_new_version || local_version == 0) {
            local_version = context_.udp_peer_coord->BumpEndpointVersion(local_scope_key);
        }
        context_.udp_peer_coord->SetState(
            local_scope_key,
            context_.session_allows_peer_direct(session) ? PeerEndpointState::OfferPending
                                                         : PeerEndpointState::RelayOnly);
        session->last_peer_offer_announce_ms = monotonic_millis();

        PacketTunnelServiceContext::SessionList peers;
        {
            std::lock_guard<std::mutex> lock(*context_.session_mutex);
            peers = context_.collect_udp_offer_peers(session);
        }

        const std::vector<TcpDirectCandidate> local_candidates =
            context_.build_udp_direct_candidates(session);
        if (local_candidates.empty()) {
            Logger::warning("[" + context_.server_name +
                            "|IP Tunnel] 编码对等端提议失败 " + local_scope_label);
            return;
        }

        for (size_t i = 0; i < peers.size(); ++i) {
            const PacketTunnelServiceContext::SessionPtr& peer = peers[i];
            const std::string peer_scope_label = context_.describe_scoped_session(peer);
            const std::string peer_scope_key =
                context_.build_scoped_virtual_ip_key(peer->server_key, peer->virtual_ip_be);
            uint64_t peer_version = context_.udp_peer_coord->GetEndpointVersion(peer_scope_key);
            if (force_new_version || peer_version == 0) {
                peer_version = context_.udp_peer_coord->BumpEndpointVersion(peer_scope_key);
                context_.udp_peer_coord->SetState(
                    peer_scope_key,
                    context_.session_allows_peer_direct(peer) ? PeerEndpointState::OfferPending
                                                              : PeerEndpointState::RelayOnly);
            }

            if (!context_.session_allows_peer_direct(session) ||
                !context_.session_allows_peer_direct(peer)) {
                if (context_.session_allows_peer_direct(session)) {
                    SendPeerDisableNotice(session,
                                          peer->virtual_ip_be,
                                          peer_version,
                                          packet_tunnel::kPeerDisableReasonCooldown);
                }
                if (context_.session_allows_peer_direct(peer)) {
                    SendPeerDisableNotice(peer,
                                          session->virtual_ip_be,
                                          local_version,
                                          packet_tunnel::kPeerDisableReasonCooldown);
                }
                Logger::debug("[" + context_.server_name +
                              "|IP Tunnel] 跳过对等端提议，双方仅允许中转 " +
                              local_scope_label + " <-> " + peer_scope_label);
                continue;
            }

            const std::vector<TcpDirectCandidate> peer_candidates =
                context_.build_udp_direct_candidates(peer);
            if (peer_candidates.empty()) {
                Logger::warning("[" + context_.server_name +
                                "|IP Tunnel] 编码对等端提议失败 " + peer_scope_label);
                continue;
            }

            size_t sent_local_candidates = 0;
            for (size_t c = 0; c < local_candidates.size(); ++c) {
                std::vector<uint8_t> local_offer_payload;
                if (encode_tcp_candidate_peer_offer_payload(session->virtual_ip_be,
                                                            local_version,
                                                            local_candidates[c],
                                                            &local_offer_payload) &&
                    context_.send_frame(peer,
                                        packet_tunnel::kFramePeerOffer,
                                        local_offer_payload.data(),
                                        local_offer_payload.size())) {
                    ++sent_local_candidates;
                }
            }

            size_t sent_peer_candidates = 0;
            for (size_t c = 0; c < peer_candidates.size(); ++c) {
                std::vector<uint8_t> peer_offer_payload;
                if (encode_tcp_candidate_peer_offer_payload(peer->virtual_ip_be,
                                                            peer_version,
                                                            peer_candidates[c],
                                                            &peer_offer_payload) &&
                    context_.send_frame(session,
                                        packet_tunnel::kFramePeerOffer,
                                        peer_offer_payload.data(),
                                        peer_offer_payload.size())) {
                    ++sent_peer_candidates;
                }
            }

            Logger::debug("[" + context_.server_name + "|IP Tunnel] 已广播UDP对等端提议 " +
                          local_scope_label + " <-> " + peer_scope_label +
                          " 本地候选=" + std::to_string(sent_local_candidates) +
                          " 对端候选=" + std::to_string(sent_peer_candidates));
        }

        LogPeerSnapshot(*context_.udp_peer_coord);
    }

    void AnnounceTcpPeerOffersForSession(const PacketTunnelServiceContext::SessionPtr& session,
                                         bool force_new_version) const {
        if (!session || !session->active || session->use_udp ||
            session->tcp_direct_listen_port == 0) {
            return;
        }

        const std::string local_scope_key =
            context_.build_scoped_virtual_ip_key(session->server_key, session->virtual_ip_be);
        uint64_t local_version = context_.tcp_peer_coord->GetEndpointVersion(local_scope_key);
        if (force_new_version || local_version == 0) {
            local_version = context_.tcp_peer_coord->BumpEndpointVersion(local_scope_key);
        }
        context_.tcp_peer_coord->SetState(local_scope_key, PeerEndpointState::OfferPending);

        const std::vector<TcpDirectCandidate> local_candidates =
            context_.build_tcp_direct_candidates(session);
        if (local_candidates.empty()) {
            Logger::warning("[" + context_.server_name +
                            "|IP Tunnel] 编码TCP对等端提议失败 " +
                            context_.describe_scoped_session(session));
            return;
        }

        PacketTunnelServiceContext::SessionList peers;
        {
            std::lock_guard<std::mutex> lock(*context_.session_mutex);
            peers = context_.collect_tcp_offer_peers(session);
        }

        for (size_t i = 0; i < peers.size(); ++i) {
            const PacketTunnelServiceContext::SessionPtr& peer = peers[i];
            const std::vector<TcpDirectCandidate> peer_candidates =
                context_.build_tcp_direct_candidates(peer);
            if (peer_candidates.empty()) {
                continue;
            }

            const std::string peer_scope_key =
                context_.build_scoped_virtual_ip_key(peer->server_key, peer->virtual_ip_be);
            uint64_t peer_version = context_.tcp_peer_coord->GetEndpointVersion(peer_scope_key);
            if (force_new_version || peer_version == 0) {
                peer_version = context_.tcp_peer_coord->BumpEndpointVersion(peer_scope_key);
            }
            context_.tcp_peer_coord->SetState(peer_scope_key, PeerEndpointState::OfferPending);

            size_t sent_local_candidates = 0;
            for (size_t c = 0; c < local_candidates.size(); ++c) {
                std::vector<uint8_t> local_offer_payload;
                if (encode_tcp_candidate_peer_offer_payload(session->virtual_ip_be,
                                                            local_version,
                                                            local_candidates[c],
                                                            &local_offer_payload) &&
                    context_.send_frame(peer,
                                        packet_tunnel::kFrameTcpPeerOffer,
                                        local_offer_payload.data(),
                                        local_offer_payload.size())) {
                    ++sent_local_candidates;
                }
            }

            size_t sent_peer_candidates = 0;
            for (size_t c = 0; c < peer_candidates.size(); ++c) {
                std::vector<uint8_t> peer_offer_payload;
                if (encode_tcp_candidate_peer_offer_payload(peer->virtual_ip_be,
                                                            peer_version,
                                                            peer_candidates[c],
                                                            &peer_offer_payload) &&
                    context_.send_frame(session,
                                        packet_tunnel::kFrameTcpPeerOffer,
                                        peer_offer_payload.data(),
                                        peer_offer_payload.size())) {
                    ++sent_peer_candidates;
                }
            }

            Logger::debug("[" + context_.server_name + "|IP Tunnel] 已广播TCP对等端提议 " +
                          local_scope_key + " <-> " + peer_scope_key +
                          " 本地候选=" + std::to_string(sent_local_candidates) +
                          " 对端候选=" + std::to_string(sent_peer_candidates));
        }
    }

    bool RoutePeerSignalFrame(const PacketTunnelServiceContext::SessionPtr& sender_session,
                              uint8_t frame_type,
                              const ParsedPeerSignalFrame& signal) const {
        if (!sender_session || !sender_session->active || !sender_session->use_udp) {
            return false;
        }
        if (context_.is_peer_direct_excluded_session(sender_session)) {
            Logger::debug("[IP Tunnel|" + sender_session->session_uuid + "] 已抑制" +
                          packet_tunnel_frame_name(frame_type) +
                          "，来源会话被排除出直连 " +
                          context_.describe_scoped_session(sender_session));
            return true;
        }

        PacketTunnelLogExpiredPeerCoordStates(context_.udp_peer_coord, context_);

        PacketTunnelServiceContext::SessionPtr target_session;
        {
            std::lock_guard<std::mutex> lock(*context_.session_mutex);
            target_session =
                context_.registry->FindUdpLocked(sender_session->server_key,
                                                 signal.peer_virtual_ip_be);
        }

        if (!target_session || !target_session->active || !target_session->use_udp) {
            return false;
        }
        if (context_.is_peer_direct_excluded_session(target_session)) {
            Logger::debug("[IP Tunnel|" + sender_session->session_uuid + "] 已抑制" +
                          packet_tunnel_frame_name(frame_type) +
                          "，目标会话被排除出直连 " +
                          context_.describe_scoped_session(target_session));
            return true;
        }

        const std::string sender_scope_key =
            context_.build_scoped_virtual_ip_key(sender_session->server_key,
                                                 sender_session->virtual_ip_be);
        const std::string target_scope_key =
            context_.build_scoped_virtual_ip_key(target_session->server_key,
                                                 target_session->virtual_ip_be);
        const std::string sender_scope_label =
            context_.describe_scoped_session(sender_session);
        const std::string target_scope_label =
            context_.describe_scoped_session(target_session);
        if (!context_.session_allows_peer_direct(sender_session) ||
            !context_.session_allows_peer_direct(target_session)) {
            if (context_.session_allows_peer_direct(sender_session)) {
                const uint64_t target_version =
                    context_.udp_peer_coord->GetEndpointVersion(target_scope_key);
                SendPeerDisableNotice(sender_session,
                                      target_session->virtual_ip_be,
                                      target_version,
                                      packet_tunnel::kPeerDisableReasonCooldown);
            }
            Logger::debug("[IP Tunnel|" + sender_session->session_uuid + "] 抑制" +
                          packet_tunnel_frame_name(frame_type) +
                          "，双方仅中转 " + sender_scope_label + " -> " +
                          target_scope_label);
            return true;
        }

        uint64_t sender_version = context_.udp_peer_coord->GetEndpointVersion(sender_scope_key);
        if (sender_version == 0) {
            sender_version = context_.udp_peer_coord->BumpEndpointVersion(sender_scope_key);
        }

        std::vector<uint8_t> payload;
        if (!encode_peer_signal_payload(sender_session->virtual_ip_be,
                                        sender_version,
                                        signal.nonce,
                                        &payload)) {
            return false;
        }

        if (!context_.send_frame(target_session, frame_type, payload.data(), payload.size())) {
            return false;
        }

        context_.udp_peer_coord->ObservePeerFrame(
            sender_scope_key,
            sender_version,
            frame_type == packet_tunnel::kFramePeerKeepalive ? PeerEndpointState::Active
                                                             : PeerEndpointState::OfferPending);

        Logger::debug("[IP Tunnel|" + sender_session->session_uuid + "] 中转 " +
                      packet_tunnel_frame_name(frame_type) + " " +
                      sender_scope_label + " -> " + target_scope_label +
                      " 随机值=" + std::to_string(signal.nonce) +
                      " 版本=" + std::to_string(sender_version));
        LogPeerSnapshot(*context_.udp_peer_coord);
        return true;
    }

    bool RoutePeerDisableFrame(const PacketTunnelServiceContext::SessionPtr& sender_session,
                               const ParsedPeerDisableFrame& disable) const {
        if (!sender_session || !sender_session->active || !sender_session->use_udp) {
            return false;
        }
        if (context_.is_peer_direct_excluded_session(sender_session)) {
            Logger::debug("[IP Tunnel|" + sender_session->session_uuid +
                          "] 已抑制对等端禁用，来源会话被排除出直连 " +
                          context_.describe_scoped_session(sender_session));
            return true;
        }

        PacketTunnelLogExpiredPeerCoordStates(context_.udp_peer_coord, context_);

        PacketTunnelServiceContext::SessionPtr target_session;
        {
            std::lock_guard<std::mutex> lock(*context_.session_mutex);
            target_session =
                context_.registry->FindUdpLocked(sender_session->server_key,
                                                 disable.peer_virtual_ip_be);
        }

        if (!target_session || !target_session->active || !target_session->use_udp) {
            return false;
        }
        if (context_.is_peer_direct_excluded_session(target_session)) {
            Logger::debug("[IP Tunnel|" + sender_session->session_uuid +
                          "] 已抑制对等端禁用，目标会话被排除出直连 " +
                          context_.describe_scoped_session(target_session));
            return true;
        }

        const std::string sender_scope_key =
            context_.build_scoped_virtual_ip_key(sender_session->server_key,
                                                 sender_session->virtual_ip_be);
        uint64_t sender_version = context_.udp_peer_coord->GetEndpointVersion(sender_scope_key);
        if (sender_version == 0) {
            sender_version = context_.udp_peer_coord->BumpEndpointVersion(sender_scope_key);
        }

        std::vector<uint8_t> payload(packet_tunnel::kPeerDisablePayloadSize, 0);
        packet_tunnel::write_u32_be(payload.data(), ntohl(sender_session->virtual_ip_be));
        packet_tunnel::write_u64_be(payload.data() + 4, sender_version);
        payload[12] = disable.reason;

        if (!context_.send_frame(target_session,
                                 packet_tunnel::kFramePeerDisable,
                                 payload.data(),
                                 payload.size())) {
            return false;
        }

        context_.udp_peer_coord->ObservePeerFrame(sender_scope_key,
                                                  sender_version,
                                                  PeerEndpointState::RelayOnly);
        Logger::debug("[IP Tunnel|" + sender_session->session_uuid + "] 中转对等端禁用 " +
                      context_.describe_scoped_session(sender_session) + " -> " +
                      context_.describe_scoped_session(target_session) +
                      " 原因=" + std::to_string(static_cast<int>(disable.reason)) +
                      " 版本=" + std::to_string(sender_version));
        LogPeerSnapshot(*context_.udp_peer_coord);
        return true;
    }

private:
    bool SendPeerDisableNotice(const PacketTunnelServiceContext::SessionPtr& session,
                               uint32_t peer_virtual_ip_be,
                               uint64_t endpoint_version,
                               uint8_t reason) const {
        if (!session || !session->active || !session->use_udp) {
            return false;
        }

        std::vector<uint8_t> payload(packet_tunnel::kPeerDisablePayloadSize, 0);
        packet_tunnel::write_u32_be(payload.data(), ntohl(peer_virtual_ip_be));
        packet_tunnel::write_u64_be(payload.data() + 4, endpoint_version);
        payload[12] = reason;
        return context_.send_frame(session,
                                   packet_tunnel::kFramePeerDisable,
                                   payload.data(),
                                   payload.size());
    }

    void LogPeerSnapshot(const PeerCoord& peer_coord) const {
        std::ostringstream ss;
        std::vector<PeerCoordStatus> snapshot = peer_coord.Snapshot();
        for (size_t i = 0; i < snapshot.size(); ++i) {
            if (i != 0) {
                ss << "; ";
            }
            ss << snapshot[i].peer_virtual_ip
               << "[" << PacketTunnelPeerEndpointStateName(snapshot[i].state)
               << " 版本=" << snapshot[i].endpoint_version << "]";
        }
        Logger::debug("[" + context_.server_name + "|IP Tunnel] 对等端快照 " +
                      (snapshot.empty() ? std::string("无") : ss.str()));
    }

    const PacketTunnelServiceContext& context_;
};

#endif
