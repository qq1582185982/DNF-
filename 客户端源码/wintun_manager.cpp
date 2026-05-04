#include "wintun_manager.h"

#include "embedded_wintun.h"
#include "wintun.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ws2tcpip.h>
#include <sstream>
#include <vector>

void PacketTunnelWarnLog(const std::string& msg);

namespace {

const char kDefaultAdapterName[] = "DNFProxyWintun";
const WCHAR kTunnelType[] = L"DNFProxy";
const DWORD kRingCapacity = 0x1000000;
const DWORD kWriteRetryDelayMs = 1;
const int kWriteRetryCount = 16;
const DWORD kSlowWintunWriteWarnMs = 10;
const WCHAR kTempSubdir[] = L"DNFProxy\\Wintun";

std::wstring GetWintunTempDir() {
    WCHAR temp_path[MAX_PATH] = {};
    DWORD len = GetTempPathW(MAX_PATH, temp_path);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }

    std::wstring dir = temp_path;
    if (!dir.empty() && dir.back() != L'\\') {
        dir.push_back(L'\\');
    }
    dir += kTempSubdir;
    CreateDirectoryW((std::wstring(temp_path) + L"DNFProxy").c_str(), NULL);
    CreateDirectoryW(dir.c_str(), NULL);
    return dir;
}

bool EnsureEmbeddedFile(const std::wstring& path, const uint8_t* data, size_t size) {
    WIN32_FILE_ATTRIBUTE_DATA file_info = {};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &file_info)) {
        ULONGLONG file_size = (static_cast<ULONGLONG>(file_info.nFileSizeHigh) << 32) | file_info.nFileSizeLow;
        if (file_size == size) {
            return true;
        }
    }

    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(file, data, static_cast<DWORD>(size), &written, NULL);
    CloseHandle(file);
    return ok && written == size;
}

bool ParseIpv4Cidr(const std::string& cidr, std::string* network, std::string* mask) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        return false;
    }

    std::string ip = cidr.substr(0, slash);
    int prefix_length = atoi(cidr.c_str() + slash + 1);
    if (prefix_length < 0 || prefix_length > 32) {
        return false;
    }

    IN_ADDR addr = {};
    if (InetPtonA(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }

    uint32_t ip_host = ntohl(addr.S_un.S_addr);
    uint32_t mask_host = (prefix_length == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix_length));
    uint32_t network_host = ip_host & mask_host;

    IN_ADDR network_addr = {};
    network_addr.S_un.S_addr = htonl(network_host);
    IN_ADDR mask_addr = {};
    mask_addr.S_un.S_addr = htonl(mask_host);

    char network_buf[INET_ADDRSTRLEN] = {};
    char mask_buf[INET_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET, &network_addr, network_buf, sizeof(network_buf)) == NULL ||
        InetNtopA(AF_INET, &mask_addr, mask_buf, sizeof(mask_buf)) == NULL) {
        return false;
    }

    if (network != NULL) {
        *network = network_buf;
    }
    if (mask != NULL) {
        *mask = mask_buf;
    }
    return true;
}

std::wstring BuildWindowsErrorMessage(const std::wstring& prefix, DWORD error) {
    wchar_t* buffer = NULL;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    FormatMessageW(flags, NULL, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, NULL);

    std::wstringstream stream;
    stream << prefix << L" (错误=" << error << L")";
    if (buffer != NULL) {
        std::wstring detail(buffer);
        while (!detail.empty() && (detail.back() == L'\r' || detail.back() == L'\n')) {
            detail.pop_back();
        }
        if (!detail.empty()) {
            stream << L": " << detail;
        }
        LocalFree(buffer);
    }
    return stream.str();
}

std::wstring Utf8ToWideLocal(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (required <= 1) {
        return std::wstring();
    }

    std::wstring wide(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wide[0], required);
    return wide;
}

bool IsTruthyEnv(const char* name) {
    size_t required = 0;
    getenv_s(&required, NULL, 0, name);
    if (required == 0) {
        return false;
    }

    std::string value(required - 1, '\0');
    getenv_s(&required, &value[0], required, name);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

std::string GetAdapterName(const TunnelLeaseRuntimeConfig& config) {
    return config.adapter_name.empty() ? std::string(kDefaultAdapterName) : config.adapter_name;
}

std::string EscapeQuotedCommandValue(std::string value) {
    std::replace(value.begin(), value.end(), '"', '\'');
    return value;
}

int ExecuteCommandSilent(const std::string& command) {
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    std::string cmdline = "cmd.exe /c " + command;
    std::vector<char> mutable_cmd(cmdline.begin(), cmdline.end());
    mutable_cmd.push_back('\0');

    if (!CreateProcessA(NULL, mutable_cmd.data(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }

    WaitForSingleObject(pi.hProcess, 30000);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}

std::wstring CommandError(const wchar_t* action, const std::string& command, int exit_code) {
    std::wstringstream stream;
    stream << action << L"失败 (退出码=" << exit_code << L"): ";
    stream << Utf8ToWideLocal(command);
    return stream.str();
}

HMODULE LoadWintunModuleFromDisk() {
    std::wstring temp_dir = GetWintunTempDir();
    if (!temp_dir.empty()) {
        std::wstring dll_path = temp_dir + L"\\wintun.dll";
        if (EnsureEmbeddedFile(dll_path, EMBEDDED_WINTUN_DLL, EMBEDDED_WINTUN_DLL_SIZE)) {
            HMODULE module = LoadLibraryW(dll_path.c_str());
            if (module != NULL) {
                return module;
            }
        }
    }

    WCHAR exe_path[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, exe_path, MAX_PATH) == 0) {
        return LoadLibraryW(L"wintun.dll");
    }

    WCHAR* slash = wcsrchr(exe_path, L'\\');
    if (slash != NULL) {
        *slash = L'\0';
    }

    std::wstring dll_path = exe_path;
    dll_path += L"\\wintun.dll";

    HMODULE module = LoadLibraryW(dll_path.c_str());
    if (module != NULL) {
        return module;
    }
    return LoadLibraryW(L"wintun.dll");
}

}  // namespace

WintunManager::WintunManager()
    : active_(false),
      module_(NULL),
      adapter_(NULL),
      session_(NULL),
      create_adapter_(NULL),
      open_adapter_(NULL),
      close_adapter_(NULL),
      get_adapter_luid_(NULL),
      get_running_driver_version_(NULL),
      start_session_(NULL),
      end_session_(NULL),
      get_read_wait_event_(NULL),
      receive_packet_(NULL),
      release_receive_packet_(NULL),
      allocate_send_packet_(NULL),
      send_packet_(NULL),
      interface_index_(0) {}

WintunManager::~WintunManager() {
    Cleanup();
}

std::wstring WintunManager::Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (required <= 1) {
        return std::wstring();
    }

    std::wstring wide(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &wide[0], required);
    return wide;
}

bool WintunManager::HasBasicRuntimeConfig(const TunnelLeaseRuntimeConfig& config) {
    return !config.server_virtual_ip.empty() &&
           !config.virtual_ip.empty() &&
           !config.subnet_mask.empty() &&
           !config.gateway_ip.empty();
}

bool WintunManager::LoadRuntime(std::wstring* error_msg) {
    if (module_ != NULL) {
        return true;
    }

    module_ = LoadWintunModuleFromDisk();
    if (module_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = BuildWindowsErrorMessage(L"无法加载 wintun.dll", GetLastError());
        }
        return false;
    }

    create_adapter_ = reinterpret_cast<CreateAdapterFn>(GetProcAddress(module_, "WintunCreateAdapter"));
    open_adapter_ = reinterpret_cast<OpenAdapterFn>(GetProcAddress(module_, "WintunOpenAdapter"));
    close_adapter_ = reinterpret_cast<CloseAdapterFn>(GetProcAddress(module_, "WintunCloseAdapter"));
    get_adapter_luid_ = reinterpret_cast<GetAdapterLuidFn>(GetProcAddress(module_, "WintunGetAdapterLUID"));
    get_running_driver_version_ = reinterpret_cast<GetRunningDriverVersionFn>(
        GetProcAddress(module_, "WintunGetRunningDriverVersion"));
    start_session_ = reinterpret_cast<StartSessionFn>(GetProcAddress(module_, "WintunStartSession"));
    end_session_ = reinterpret_cast<EndSessionFn>(GetProcAddress(module_, "WintunEndSession"));
    get_read_wait_event_ = reinterpret_cast<GetReadWaitEventFn>(GetProcAddress(module_, "WintunGetReadWaitEvent"));
    receive_packet_ = reinterpret_cast<ReceivePacketFn>(GetProcAddress(module_, "WintunReceivePacket"));
    release_receive_packet_ = reinterpret_cast<ReleaseReceivePacketFn>(GetProcAddress(module_, "WintunReleaseReceivePacket"));
    allocate_send_packet_ = reinterpret_cast<AllocateSendPacketFn>(GetProcAddress(module_, "WintunAllocateSendPacket"));
    send_packet_ = reinterpret_cast<SendPacketFn>(GetProcAddress(module_, "WintunSendPacket"));

    if (create_adapter_ == NULL || open_adapter_ == NULL || close_adapter_ == NULL || get_adapter_luid_ == NULL ||
        get_running_driver_version_ == NULL || start_session_ == NULL || end_session_ == NULL ||
        get_read_wait_event_ == NULL || receive_packet_ == NULL || release_receive_packet_ == NULL ||
        allocate_send_packet_ == NULL || send_packet_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"wintun.dll 缺少必需导出函数";
        }
        Cleanup();
        return false;
    }

    return true;
}

bool WintunManager::EnsureAdapter(std::wstring* error_msg) {
    if (adapter_ != NULL) {
        return true;
    }

    const std::wstring adapter_name = Utf8ToWideLocal(GetAdapterName(current_config_));

    adapter_ = open_adapter_(adapter_name.c_str());
    if (adapter_ == NULL) {
        adapter_ = create_adapter_(adapter_name.c_str(), kTunnelType, NULL);
    }

    if (adapter_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = BuildWindowsErrorMessage(L"无法打开或创建 Wintun 适配器", GetLastError());
        }
        return false;
    }

    NET_LUID luid = {};
    get_adapter_luid_(adapter_, &luid);
    if (ConvertInterfaceLuidToIndex(&luid, &interface_index_) != NO_ERROR || interface_index_ == 0) {
        if (error_msg != NULL) {
            *error_msg = L"无法解析 Wintun 接口索引";
        }
        return false;
    }

    return true;
}

bool WintunManager::StartSession(std::wstring* error_msg) {
    if (session_ != NULL) {
        return true;
    }

    session_ = start_session_(adapter_, kRingCapacity);
    if (session_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = BuildWindowsErrorMessage(L"无法启动 Wintun 会话", GetLastError());
        }
        return false;
    }
    return true;
}

bool WintunManager::ConfigureAddress(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    const std::string adapter_name = EscapeQuotedCommandValue(GetAdapterName(config));
    ExecuteCommandSilent("netsh interface ipv4 delete route prefix=0.0.0.0/0 interface=\"" +
                         adapter_name + "\" store=active >nul 2>&1");

    const std::string base =
        "netsh interface ipv4 set address name=\"" + adapter_name + "\" source=static address=" +
        config.virtual_ip + " mask=" + config.subnet_mask + " gateway=none store=active >nul 2>&1";
    int ret = ExecuteCommandSilent(base);
    if (ret == 0) {
        return true;
    }

    const std::string fallback =
        "netsh interface ip set address name=\"" + adapter_name + "\" static " +
        config.virtual_ip + " " + config.subnet_mask + " none >nul 2>&1";
    ret = ExecuteCommandSilent(fallback);
    if (ret != 0 && error_msg != NULL) {
        *error_msg = CommandError(L"设置 Wintun 地址", fallback, ret);
    }
    return ret == 0;
}

bool WintunManager::ConfigureMtu(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    if (config.mtu == 0) {
        return true;
    }

    std::ostringstream command;
    command << "netsh interface ipv4 set subinterface \""
            << EscapeQuotedCommandValue(GetAdapterName(config))
            << "\" mtu=" << config.mtu
            << " store=active >nul 2>&1";

    int ret = ExecuteCommandSilent(command.str());
    if (ret != 0 && error_msg != NULL) {
        *error_msg = CommandError(L"设置 Wintun MTU", command.str(), ret);
    }
    return ret == 0;
}

bool WintunManager::ConfigureRoutes(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    if (interface_index_ == 0) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 接口索引不可用";
        }
        return false;
    }

    for (size_t i = 0; i < config.routes.size(); ++i) {
        const std::string& cidr = config.routes[i].cidr;
        std::string network;
        std::string mask;
        if (!ParseIpv4Cidr(cidr, &network, &mask)) {
            if (error_msg != NULL) {
                *error_msg = L"无效的 IPv4 路由 CIDR: " + Utf8ToWideLocal(cidr);
            }
            return false;
        }

        std::string delete_cmd =
            "route delete " + network + " mask " + mask +
            " IF " + std::to_string(interface_index_) + " >nul 2>&1";
        ExecuteCommandSilent(delete_cmd);

        std::string add_cmd =
            "route add " + network + " mask " + mask +
            " 0.0.0.0 IF " + std::to_string(interface_index_) +
            " metric 1 >nul 2>&1";
        int ret = ExecuteCommandSilent(add_cmd);
        if (ret != 0) {
            if (error_msg != NULL) {
                *error_msg = CommandError(L"添加 Wintun 路由", add_cmd, ret);
            }
            return false;
        }
    }
    return true;
}

bool WintunManager::ConfigureInterface(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    const std::string adapter_name = EscapeQuotedCommandValue(GetAdapterName(config));
    const std::string enable_cmd =
        "netsh interface set interface name=\"" + adapter_name + "\" enable >nul 2>&1";
    int enable_ret = ExecuteCommandSilent(enable_cmd);
    if (enable_ret != 0 && error_msg != NULL) {
        *error_msg = CommandError(L"启用 Wintun 接口", enable_cmd, enable_ret);
        return false;
    }

    if (!ConfigureAddress(config, error_msg)) {
        return false;
    }
    if (!ConfigureMtu(config, error_msg)) {
        return false;
    }
    if (!ConfigureRoutes(config, error_msg)) {
        return false;
    }
    return true;
}

bool WintunManager::Setup(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    Cleanup();

    if (!HasBasicRuntimeConfig(config)) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 运行时配置不完整";
        }
        return false;
    }

    current_config_ = config;

    if (!LoadRuntime(error_msg)) {
        return false;
    }
    if (!EnsureAdapter(error_msg)) {
        Cleanup();
        return false;
    }
    if (!StartSession(error_msg)) {
        Cleanup();
        return false;
    }

    active_ = true;
    return true;
}

bool WintunManager::ActivateNetwork(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    if (!session_ || !adapter_) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 会话未激活";
        }
        return false;
    }

    if (!ConfigureInterface(config, error_msg)) {
        return false;
    }
    return true;
}

bool WintunManager::ReadPacket(std::vector<uint8_t>* packet, DWORD wait_ms, std::wstring* error_msg) {
    if (packet == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 读包输出缓冲区为空";
        }
        return false;
    }
    packet->clear();

    if (session_ == NULL || receive_packet_ == NULL || release_receive_packet_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 会话尚未就绪";
        }
        return false;
    }

    for (;;) {
        DWORD packet_size = 0;
        BYTE* incoming = receive_packet_(session_, &packet_size);
        if (incoming != NULL) {
            packet->assign(incoming, incoming + packet_size);
            release_receive_packet_(session_, incoming);
            return true;
        }

        DWORD err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) {
            HANDLE event_handle = get_read_wait_event_(session_);
            DWORD wait_ret = WaitForSingleObject(event_handle, wait_ms);
            if (wait_ret == WAIT_TIMEOUT) {
                return false;
            }
            if (wait_ret == WAIT_OBJECT_0) {
                continue;
            }
            if (error_msg != NULL) {
                *error_msg = BuildWindowsErrorMessage(L"Wintun 等待失败", GetLastError());
            }
            return false;
        }
        if (err == ERROR_HANDLE_EOF) {
            if (error_msg != NULL) {
                *error_msg = L"Wintun 适配器正在终止";
            }
            return false;
        }

        if (error_msg != NULL) {
            *error_msg = BuildWindowsErrorMessage(L"Wintun 接收失败", err);
        }
        return false;
    }
}

bool WintunManager::WritePacket(const uint8_t* packet, size_t length, std::wstring* error_msg) {
    if (packet == NULL || length == 0) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 发送包为空";
        }
        return false;
    }

    if (session_ == NULL || allocate_send_packet_ == NULL || send_packet_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"Wintun 会话尚未就绪";
        }
        return false;
    }

    BYTE* outgoing = NULL;
    DWORD last_error = ERROR_SUCCESS;
    const DWORD write_start = GetTickCount();
    int retry_count = 0;
    for (int attempt = 0; attempt < kWriteRetryCount; ++attempt) {
        outgoing = allocate_send_packet_(session_, (DWORD)length);
        if (outgoing != NULL) {
            break;
        }

        last_error = GetLastError();
        if (last_error != ERROR_BUFFER_OVERFLOW) {
            break;
        }

        retry_count = attempt + 1;
        if (attempt + 1 < kWriteRetryCount) {
            Sleep(kWriteRetryDelayMs);
        }
    }
    if (outgoing == NULL) {
        if (error_msg != NULL) {
            if (last_error == ERROR_BUFFER_OVERFLOW) {
                *error_msg = L"Wintun 发送环在重试后仍然已满";
            } else {
                *error_msg = BuildWindowsErrorMessage(L"Wintun 分配发送包失败", last_error);
            }
        }
        return false;
    }

    memcpy(outgoing, packet, length);
    send_packet_(session_, outgoing);
    const DWORD write_elapsed = GetTickCount() - write_start;
    if (retry_count > 0 || write_elapsed >= kSlowWintunWriteWarnMs) {
        PacketTunnelWarnLog("Wintun 写入延迟 耗时毫秒=" +
                            std::to_string(write_elapsed) +
                            " 重试次数=" + std::to_string(retry_count) +
                            " 长度=" + std::to_string(length));
    }
    return true;
}

void WintunManager::ResetRuntimeState() {
    create_adapter_ = NULL;
    open_adapter_ = NULL;
    close_adapter_ = NULL;
    get_adapter_luid_ = NULL;
    get_running_driver_version_ = NULL;
    start_session_ = NULL;
    end_session_ = NULL;
    get_read_wait_event_ = NULL;
    receive_packet_ = NULL;
    release_receive_packet_ = NULL;
    allocate_send_packet_ = NULL;
    send_packet_ = NULL;
    interface_index_ = 0;
}

void WintunManager::Cleanup() {
    active_ = false;

    if (session_ != NULL && end_session_ != NULL) {
        end_session_(session_);
        session_ = NULL;
    }

    if (adapter_ != NULL && close_adapter_ != NULL) {
        close_adapter_(adapter_);
        adapter_ = NULL;
    }

    if (module_ != NULL) {
        FreeLibrary(module_);
        module_ = NULL;
    }

    ResetRuntimeState();
}
