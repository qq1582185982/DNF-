#ifndef NAT_PMP_HELPER_H_
#define NAT_PMP_HELPER_H_

#include <stdint.h>
#include <stdlib.h>

#include <cstring>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#endif

namespace nat_pmp {

#if defined(_WIN32)
typedef SOCKET socket_handle_t;
#else
typedef int socket_handle_t;
#endif

enum class Protocol : uint8_t {
    Udp = 1,
    Tcp = 2
};

struct PortMapping {
    uint32_t public_ipv4_be;
    uint16_t internal_port;
    uint16_t external_port;
    uint32_t lifetime_seconds;

    PortMapping()
        : public_ipv4_be(0),
          internal_port(0),
          external_port(0),
          lifetime_seconds(0) {}
};

inline std::string Ipv4BeToString(uint32_t ipv4_be) {
    char buffer[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &ipv4_be, buffer, sizeof(buffer)) == NULL) {
        return "0.0.0.0";
    }
    return buffer;
}

inline const char* ResultCodeToString(uint16_t code) {
    switch (code) {
    case 0:
        return "success";
    case 1:
        return "unsupported_version";
    case 2:
        return "not_authorized";
    case 3:
        return "network_failure";
    case 4:
        return "out_of_resources";
    case 5:
        return "unsupported_opcode";
    default:
        return "unknown";
    }
}

inline bool ExtractIpv4FromSockaddr(const sockaddr_storage& addr, uint32_t* out_ipv4_be) {
    if (out_ipv4_be == NULL || addr.ss_family != AF_INET) {
        return false;
    }
    *out_ipv4_be = reinterpret_cast<const sockaddr_in*>(&addr)->sin_addr.s_addr;
    return true;
}

#if defined(_WIN32)
inline bool ResolveGatewayForRouteHint(const sockaddr_storage& route_hint,
                                       uint32_t* out_gateway_be,
                                       std::string* error) {
    if (out_gateway_be == NULL) {
        return false;
    }

    uint32_t local_ipv4_be = 0;
    if (!ExtractIpv4FromSockaddr(route_hint, &local_ipv4_be) || local_ipv4_be == 0) {
        if (error != NULL) {
            *error = "route hint is not ipv4";
        }
        return false;
    }

    ULONG flags = GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER |
                  GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG buffer_size = 16 * 1024;
    std::string buffer(buffer_size, '\0');
    IP_ADAPTER_ADDRESSES* adapters =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&buffer[0]);
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &buffer_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.assign(buffer_size, '\0');
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&buffer[0]);
        ret = GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &buffer_size);
    }
    if (ret != NO_ERROR) {
        if (error != NULL) {
            *error = "GetAdaptersAddresses failed";
        }
        return false;
    }

    for (IP_ADAPTER_ADDRESSES* adapter = adapters;
         adapter != NULL;
         adapter = adapter->Next) {
        bool address_match = false;
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == NULL ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            const sockaddr_in* addr4 =
                reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
            if (addr4->sin_addr.s_addr == local_ipv4_be) {
                address_match = true;
                break;
            }
        }
        if (!address_match) {
            continue;
        }

        for (IP_ADAPTER_GATEWAY_ADDRESS_LH* gateway = adapter->FirstGatewayAddress;
             gateway != NULL;
             gateway = gateway->Next) {
            if (gateway->Address.lpSockaddr == NULL ||
                gateway->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            const sockaddr_in* gateway_addr =
                reinterpret_cast<const sockaddr_in*>(gateway->Address.lpSockaddr);
            if (gateway_addr->sin_addr.s_addr != 0) {
                *out_gateway_be = gateway_addr->sin_addr.s_addr;
                return true;
            }
        }
    }

    if (error != NULL) {
        *error = "gateway not found";
    }
    return false;
}
#else
inline bool ResolveLinuxInterfaceName(uint32_t local_ipv4_be, std::string* out_ifname) {
    ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) {
        return false;
    }

    bool found = false;
    for (ifaddrs* ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL ||
            ifa->ifa_addr->sa_family != AF_INET ||
            ifa->ifa_name == NULL) {
            continue;
        }
        const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        if (addr4->sin_addr.s_addr == local_ipv4_be) {
            if (out_ifname != NULL) {
                *out_ifname = ifa->ifa_name;
            }
            found = true;
            break;
        }
    }

    freeifaddrs(interfaces);
    return found;
}

inline bool ResolveGatewayForRouteHint(const sockaddr_storage& route_hint,
                                       uint32_t* out_gateway_be,
                                       std::string* error) {
    if (out_gateway_be == NULL) {
        return false;
    }

    uint32_t local_ipv4_be = 0;
    if (!ExtractIpv4FromSockaddr(route_hint, &local_ipv4_be) || local_ipv4_be == 0) {
        if (error != NULL) {
            *error = "route hint is not ipv4";
        }
        return false;
    }

    std::string preferred_ifname;
    ResolveLinuxInterfaceName(local_ipv4_be, &preferred_ifname);

    std::ifstream route_file("/proc/net/route");
    if (!route_file.is_open()) {
        if (error != NULL) {
            *error = "open /proc/net/route failed";
        }
        return false;
    }

    std::string line;
    std::getline(route_file, line);
    while (std::getline(route_file, line)) {
        std::istringstream iss(line);
        std::string iface;
        std::string destination_hex;
        std::string gateway_hex;
        unsigned long flags = 0;
        if (!(iss >> iface >> destination_hex >> gateway_hex >> std::hex >> flags)) {
            continue;
        }
        if (destination_hex != "00000000") {
            continue;
        }
        if ((flags & 0x2u) == 0) {
            continue;
        }
        if (!preferred_ifname.empty() && iface != preferred_ifname) {
            continue;
        }

        const unsigned long gateway_host = strtoul(gateway_hex.c_str(), NULL, 16);
        *out_gateway_be = htonl(static_cast<uint32_t>(gateway_host));
        return true;
    }

    if (error != NULL) {
        *error = "gateway not found";
    }
    return false;
}
#endif

inline bool SendRequestAndRecvResponse(socket_handle_t sock_fd,
                                       const sockaddr_in& gateway_addr,
                                       const uint8_t* request,
                                       size_t request_len,
                                       uint8_t* response,
                                       size_t response_len,
                                       int* out_received,
                                       std::string* error) {
    const int sent = sendto(sock_fd,
                            reinterpret_cast<const char*>(request),
                            static_cast<int>(request_len),
                            0,
                            reinterpret_cast<const sockaddr*>(&gateway_addr),
                            sizeof(gateway_addr));
    if (sent != static_cast<int>(request_len)) {
        if (error != NULL) {
            *error = "sendto failed";
        }
        return false;
    }

    sockaddr_in source_addr = {};
    socklen_t source_addr_len = sizeof(source_addr);
    const int received = recvfrom(sock_fd,
                                  reinterpret_cast<char*>(response),
                                  static_cast<int>(response_len),
                                  0,
                                  reinterpret_cast<sockaddr*>(&source_addr),
                                  &source_addr_len);
    if (received <= 0) {
        if (error != NULL) {
            *error = "recvfrom timeout";
        }
        return false;
    }

    if (source_addr.sin_family != AF_INET ||
        source_addr.sin_addr.s_addr != gateway_addr.sin_addr.s_addr ||
        ntohs(source_addr.sin_port) != ntohs(gateway_addr.sin_port)) {
        if (error != NULL) {
            *error = "response source mismatch";
        }
        return false;
    }

    if (out_received != NULL) {
        *out_received = received;
    }
    return true;
}

inline bool TryMapPort(const sockaddr_storage& route_hint,
                       Protocol protocol,
                       uint16_t internal_port,
                       uint32_t lifetime_seconds,
                       PortMapping* out_mapping,
                       std::string* error) {
    if (out_mapping == NULL || internal_port == 0) {
        if (error != NULL) {
            *error = "invalid arguments";
        }
        return false;
    }

    uint32_t gateway_be = 0;
    if (!ResolveGatewayForRouteHint(route_hint, &gateway_be, error)) {
        return false;
    }

    uint32_t route_hint_ipv4_be = 0;
    if (!ExtractIpv4FromSockaddr(route_hint, &route_hint_ipv4_be) || route_hint_ipv4_be == 0) {
        if (error != NULL) {
            *error = "route hint is not ipv4";
        }
        return false;
    }

#if defined(_WIN32)
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        if (error != NULL) {
            *error = "socket failed";
        }
        return false;
    }

    sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = route_hint_ipv4_be;
    bind_addr.sin_port = htons(0);
    if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
            closesocket(sock);
            if (error != NULL) {
                *error = "bind failed";
            }
            return false;
        }
    }

    DWORD timeout_ms = 180;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        if (error != NULL) {
            *error = "socket failed";
        }
        return false;
    }

    sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = route_hint_ipv4_be;
    bind_addr.sin_port = htons(0);
    if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock, reinterpret_cast<const sockaddr*>(&bind_addr), sizeof(bind_addr)) != 0) {
            close(sock);
            if (error != NULL) {
                *error = "bind failed";
            }
            return false;
        }
    }

    timeval timeout = {};
    timeout.tv_sec = 0;
    timeout.tv_usec = 180000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif

    sockaddr_in gateway_addr = {};
    gateway_addr.sin_family = AF_INET;
    gateway_addr.sin_addr.s_addr = gateway_be;
    gateway_addr.sin_port = htons(5351);

    uint8_t public_request[2] = {0, 0};
    uint8_t public_response[16] = {};
    int public_received = 0;
    bool ok = SendRequestAndRecvResponse(sock,
                                         gateway_addr,
                                         public_request,
                                         sizeof(public_request),
                                         public_response,
                                         sizeof(public_response),
                                         &public_received,
                                         error);
    if (!ok) {
#if defined(_WIN32)
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }
    if (public_received < 12 || public_response[0] != 0 || public_response[1] != 128) {
#if defined(_WIN32)
        closesocket(sock);
#else
        close(sock);
#endif
        if (error != NULL) {
            *error = "public address response invalid";
        }
        return false;
    }

    const uint16_t public_result = static_cast<uint16_t>((public_response[2] << 8) | public_response[3]);
    if (public_result != 0) {
#if defined(_WIN32)
        closesocket(sock);
#else
        close(sock);
#endif
        if (error != NULL) {
            *error = std::string("public address request failed: ") +
                     ResultCodeToString(public_result);
        }
        return false;
    }

    uint32_t public_ipv4_be = 0;
    memcpy(&public_ipv4_be, public_response + 8, sizeof(public_ipv4_be));

    uint8_t map_request[12] = {};
    map_request[0] = 0;
    map_request[1] = (protocol == Protocol::Udp) ? 1 : 2;
    map_request[4] = static_cast<uint8_t>((internal_port >> 8) & 0xFF);
    map_request[5] = static_cast<uint8_t>(internal_port & 0xFF);
    map_request[6] = static_cast<uint8_t>((internal_port >> 8) & 0xFF);
    map_request[7] = static_cast<uint8_t>(internal_port & 0xFF);
    map_request[8] = static_cast<uint8_t>((lifetime_seconds >> 24) & 0xFF);
    map_request[9] = static_cast<uint8_t>((lifetime_seconds >> 16) & 0xFF);
    map_request[10] = static_cast<uint8_t>((lifetime_seconds >> 8) & 0xFF);
    map_request[11] = static_cast<uint8_t>(lifetime_seconds & 0xFF);

    uint8_t map_response[20] = {};
    int map_received = 0;
    ok = SendRequestAndRecvResponse(sock,
                                    gateway_addr,
                                    map_request,
                                    sizeof(map_request),
                                    map_response,
                                    sizeof(map_response),
                                    &map_received,
                                    error);
#if defined(_WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
    if (!ok) {
        return false;
    }
    const uint8_t expected_opcode = static_cast<uint8_t>(
        ((protocol == Protocol::Udp) ? 1 : 2) + 128);
    if (map_received < 16 || map_response[0] != 0 || map_response[1] != expected_opcode) {
        if (error != NULL) {
            *error = "mapping response invalid";
        }
        return false;
    }

    const uint16_t mapping_result = static_cast<uint16_t>((map_response[2] << 8) | map_response[3]);
    if (mapping_result != 0) {
        if (error != NULL) {
            *error = std::string("mapping request failed: ") +
                     ResultCodeToString(mapping_result);
        }
        return false;
    }

    out_mapping->public_ipv4_be = public_ipv4_be;
    out_mapping->internal_port =
        static_cast<uint16_t>((map_response[8] << 8) | map_response[9]);
    out_mapping->external_port =
        static_cast<uint16_t>((map_response[10] << 8) | map_response[11]);
    out_mapping->lifetime_seconds =
        (static_cast<uint32_t>(map_response[12]) << 24) |
        (static_cast<uint32_t>(map_response[13]) << 16) |
        (static_cast<uint32_t>(map_response[14]) << 8) |
        static_cast<uint32_t>(map_response[15]);
    return out_mapping->external_port != 0 && out_mapping->public_ipv4_be != 0;
}

}  // namespace nat_pmp

#endif
