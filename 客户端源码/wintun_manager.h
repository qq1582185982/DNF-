#pragma once

#include "ip_lease_protocol.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <ifdef.h>

#include <string>
#include <vector>

struct TunnelLeaseRuntimeConfig {
    std::string server_virtual_ip;
    std::string virtual_ip;
    std::string subnet_mask;
    std::string gateway_ip;
    uint16_t mtu;
    std::vector<ip_tunnel::RouteEntry> routes;

    TunnelLeaseRuntimeConfig()
        : mtu(ip_tunnel::kDefaultMtu) {}
};

class WintunManager {
public:
    WintunManager();
    ~WintunManager();

    bool Setup(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg);
    bool ActivateNetwork(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg);
    bool ReadPacket(std::vector<uint8_t>* packet, DWORD wait_ms, std::wstring* error_msg);
    bool WritePacket(const uint8_t* packet, size_t length, std::wstring* error_msg);
    void Cleanup();
    bool IsActive() const { return active_; }

private:
    struct _WINTUN_ADAPTER;
    struct _TUN_SESSION;

    typedef _WINTUN_ADAPTER* WINTUN_ADAPTER_HANDLE;
    typedef _TUN_SESSION* WINTUN_SESSION_HANDLE;

    typedef WINTUN_ADAPTER_HANDLE (WINAPI *CreateAdapterFn)(LPCWSTR, LPCWSTR, const GUID*);
    typedef WINTUN_ADAPTER_HANDLE (WINAPI *OpenAdapterFn)(LPCWSTR);
    typedef void (WINAPI *CloseAdapterFn)(WINTUN_ADAPTER_HANDLE);
    typedef VOID (WINAPI *GetAdapterLuidFn)(WINTUN_ADAPTER_HANDLE, NET_LUID*);
    typedef DWORD (WINAPI *GetRunningDriverVersionFn)(void);
    typedef WINTUN_SESSION_HANDLE (WINAPI *StartSessionFn)(WINTUN_ADAPTER_HANDLE, DWORD);
    typedef void (WINAPI *EndSessionFn)(WINTUN_SESSION_HANDLE);
    typedef HANDLE (WINAPI *GetReadWaitEventFn)(WINTUN_SESSION_HANDLE);
    typedef BYTE* (WINAPI *ReceivePacketFn)(WINTUN_SESSION_HANDLE, DWORD*);
    typedef void (WINAPI *ReleaseReceivePacketFn)(WINTUN_SESSION_HANDLE, const BYTE*);
    typedef BYTE* (WINAPI *AllocateSendPacketFn)(WINTUN_SESSION_HANDLE, DWORD);
    typedef void (WINAPI *SendPacketFn)(WINTUN_SESSION_HANDLE, const BYTE*);

    static std::wstring Utf8ToWide(const std::string& value);
    static bool HasBasicRuntimeConfig(const TunnelLeaseRuntimeConfig& config);

    bool LoadRuntime(std::wstring* error_msg);
    bool EnsureAdapter(std::wstring* error_msg);
    bool StartSession(std::wstring* error_msg);
    bool ConfigureInterface(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg);
    bool ConfigureAddress(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg);
    bool ConfigureMtu(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg);
    bool ConfigureRoutes(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg);
    void ResetRuntimeState();

    bool active_;
    HMODULE module_;
    WINTUN_ADAPTER_HANDLE adapter_;
    WINTUN_SESSION_HANDLE session_;
    CreateAdapterFn create_adapter_;
    OpenAdapterFn open_adapter_;
    CloseAdapterFn close_adapter_;
    GetAdapterLuidFn get_adapter_luid_;
    GetRunningDriverVersionFn get_running_driver_version_;
    StartSessionFn start_session_;
    EndSessionFn end_session_;
    GetReadWaitEventFn get_read_wait_event_;
    ReceivePacketFn receive_packet_;
    ReleaseReceivePacketFn release_receive_packet_;
    AllocateSendPacketFn allocate_send_packet_;
    SendPacketFn send_packet_;
    NET_IFINDEX interface_index_;
};
