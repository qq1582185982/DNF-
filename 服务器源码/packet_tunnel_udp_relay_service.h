#ifndef PACKET_TUNNEL_UDP_RELAY_SERVICE_H_
#define PACKET_TUNNEL_UDP_RELAY_SERVICE_H_

#include "packet_tunnel_service_context.h"

#include <netinet/in.h>

#include <string>
#include <vector>

inline void PacketTunnelTouchSessionForService(
    const std::shared_ptr<PacketTunnelSession>& session,
    uint64_t now_ms = 0) {
    if (!session) {
        return;
    }
    if (now_ms == 0) {
        now_ms = monotonic_millis();
    }
    session->last_activity_ms.store(now_ms);
}

class UdpRelayService {
public:
    explicit UdpRelayService(const PacketTunnelServiceContext& context)
        : context_(context) {}

    bool RelayVirtualPeerPacket(const PacketTunnelServiceContext::SessionPtr& sender_session,
                                uint32_t dst_ip_be,
                                const uint8_t* payload,
                                size_t payload_len) const {
        if (!sender_session || !sender_session->active || payload == NULL || payload_len < 20) {
            return false;
        }

        uint32_t src_ip_be = 0;
        memcpy(&src_ip_be, payload + 12, sizeof(src_ip_be));
        const bool is_tcp_payload =
            PacketTunnelSessionRegistry::PacketTunnelPayloadIsTcp(payload, payload_len);
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        const bool is_udp_payload =
            payload_len >= 20 &&
            (((payload[0] >> 4) & 0x0F) == 4) &&
            payload[9] == IPPROTO_UDP &&
            ipv4_udp_ports(payload, payload_len, &src_port, &dst_port);

        PacketTunnelServiceContext::SessionPtr peer_session;
        PacketTunnelServiceContext::SessionPtr target_session;
        {
            std::lock_guard<std::mutex> lock(*context_.session_mutex);
            peer_session = context_.registry->FindUdpLocked(sender_session->server_key, dst_ip_be);
            if (is_tcp_payload) {
                target_session = context_.registry->SelectDeliveryLocked(sender_session->server_key,
                                                                         dst_ip_be,
                                                                         payload,
                                                                         payload_len);
            } else {
                target_session = peer_session;
            }
        }

        if (!target_session || !target_session->active || target_session == sender_session) {
            if (is_udp_payload && context_.maybe_log_virtual_peer_udp_relay) {
                context_.maybe_log_virtual_peer_udp_relay(sender_session,
                                                          target_session,
                                                          src_ip_be,
                                                          dst_ip_be,
                                                          src_port,
                                                          dst_port,
                                                          payload_len);
            }
            return false;
        }

        if (is_udp_payload &&
            context_.session_allows_peer_direct(sender_session) &&
            peer_session &&
            context_.session_allows_peer_direct(peer_session) &&
            (is_known_game_udp_port(src_port) || is_known_game_udp_port(dst_port))) {
            const std::string sender_scope_key =
                context_.build_scoped_virtual_ip_key(sender_session->server_key, src_ip_be);
            const std::string target_scope_key =
                context_.build_scoped_virtual_ip_key(peer_session->server_key, dst_ip_be);
            if (context_.udp_peer_coord->GetState(sender_scope_key) == PeerEndpointState::Active &&
                context_.udp_peer_coord->GetState(target_scope_key) == PeerEndpointState::Active) {
                Logger::debug("[IP Tunnel|" + sender_session->session_uuid +
                              "] 对端UDP已直连，跳过中转 src=" +
                              ipv4_be_to_string(src_ip_be) + ":" + std::to_string(src_port) +
                              " dst=" + ipv4_be_to_string(dst_ip_be) + ":" +
                              std::to_string(dst_port) +
                              " 原因=对端直连已激活");
                return true;
            }
        }

        if (is_udp_payload && context_.maybe_log_virtual_peer_udp_relay) {
            context_.maybe_log_virtual_peer_udp_relay(sender_session,
                                                      target_session,
                                                      src_ip_be,
                                                      dst_ip_be,
                                                      src_port,
                                                      dst_port,
                                                      payload_len);
        }

        if (!context_.send_frame(target_session,
                                 packet_tunnel::kFrameIpv4Packet,
                                 payload,
                                 payload_len)) {
            Logger::warning("[IP Tunnel|" + sender_session->session_uuid +
                            "] 转发虚拟对端数据包失败，目标=" +
                            context_.describe_scoped_session(target_session));
            target_session->active = false;
            if (!target_session->use_udp && target_session->client_fd >= 0) {
                shutdown(target_session->client_fd, SHUT_RDWR);
            }
            return false;
        }

        PacketTunnelTouchSessionForService(target_session);
        return true;
    }

    std::vector<PacketTunnelSessionRemoval> CleanupIdleSessions(uint64_t now_ms) const {
        std::vector<PacketTunnelSessionRemoval> removed;
        std::lock_guard<std::mutex> lock(*context_.session_mutex);
        if (context_.udp_sessions == NULL) {
            return removed;
        }

        for (PacketTunnelServiceContext::SessionMap::iterator it = context_.udp_sessions->begin();
             it != context_.udp_sessions->end();) {
            const PacketTunnelServiceContext::SessionPtr& session = it->second;
            bool should_remove = !session || !session->active;
            std::string remove_reason = should_remove ? "inactive" : "";
            if (!should_remove && session->use_udp) {
                const uint64_t last_activity_ms = session->last_activity_ms.load();
                should_remove =
                    last_activity_ms == 0 ||
                    now_ms < last_activity_ms ||
                    (now_ms - last_activity_ms) >= context_.udp_idle_timeout_ms;
                if (should_remove) {
                    remove_reason = "idle_timeout";
                }
            }

            if (!should_remove && session) {
                std::string lease_error;
                if (!context_.session_has_active_lease(session, &lease_error)) {
                    should_remove = true;
                    remove_reason = "inactive_lease";
                    if (!lease_error.empty()) {
                        remove_reason += " (" + lease_error + ")";
                    }
                }
            }

            if (!should_remove) {
                ++it;
                continue;
            }

            PacketTunnelServiceContext::SessionPtr removed_session = session;
            ++it;
            if (session) {
                removed.push_back(PacketTunnelSessionRemoval(session, remove_reason));
                context_.registry->EraseUdpLocked(removed_session);
            }
        }

        if (context_.endpoint_sessions != NULL) {
            for (PacketTunnelServiceContext::SessionMap::iterator it =
                     context_.endpoint_sessions->begin();
                 it != context_.endpoint_sessions->end();) {
                if (!it->second || !it->second->active) {
                    it = context_.endpoint_sessions->erase(it);
                } else {
                    ++it;
                }
            }
        }

        return removed;
    }

private:
    const PacketTunnelServiceContext& context_;
};

#endif
