#ifndef PACKET_TUNNEL_TCP_RELAY_SERVICE_H_
#define PACKET_TUNNEL_TCP_RELAY_SERVICE_H_

#include "packet_tunnel_service_context.h"

#include <string>
#include <vector>

class TcpRelayService {
public:
    explicit TcpRelayService(const PacketTunnelServiceContext& context)
        : context_(context) {}

    std::vector<PacketTunnelSessionRemoval> CleanupSessions(uint64_t now_ms) const {
        (void)now_ms;
        std::vector<PacketTunnelSessionRemoval> removed;
        std::lock_guard<std::mutex> lock(*context_.session_mutex);
        if (context_.tcp_sessions == NULL) {
            return removed;
        }

        for (PacketTunnelServiceContext::SessionMap::iterator it = context_.tcp_sessions->begin();
             it != context_.tcp_sessions->end();) {
            const PacketTunnelServiceContext::SessionPtr& session = it->second;
            bool should_remove = !session || !session->active || session->client_fd < 0;
            std::string remove_reason = should_remove ? "inactive" : "";

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
                context_.registry->EraseTcpLocked(removed_session);
            }
        }

        return removed;
    }

private:
    const PacketTunnelServiceContext& context_;
};

#endif
