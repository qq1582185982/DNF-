#include "wintun_manager.h"

#include "wintun.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <vector>

namespace {

const WCHAR kAdapterName[] = L"DNFProxyWintun";
const WCHAR kTunnelType[] = L"DNFProxy";
const DWORD kRingCapacity = 0x400000;

std::wstring BuildWindowsErrorMessage(const std::wstring& prefix, DWORD error) {
    wchar_t* buffer = NULL;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    FormatMessageW(flags, NULL, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, NULL);

    std::wstringstream stream;
    stream << prefix << L" (error=" << error << L")";
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
    stream << action << L" failed (exit=" << exit_code << L"): ";
    stream << Utf8ToWideLocal(command);
    return stream.str();
}

HMODULE LoadWintunModuleFromDisk() {
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
      get_running_driver_version_(NULL),
      start_session_(NULL),
      end_session_(NULL) {}

WintunManager::~WintunManager() {
    Cleanup();
}

std::string WintunManager::ReadEnvUtf8(const char* name) {
    size_t required = 0;
    getenv_s(&required, NULL, 0, name);
    if (required == 0) {
        return "";
    }

    std::string value(required - 1, '\0');
    getenv_s(&required, &value[0], required, name);
    return value;
}

std::string WintunManager::ToLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value;
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
    return !config.game_server_ip.empty() &&
           !config.virtual_ip.empty() &&
           !config.subnet_mask.empty() &&
           !config.gateway_ip.empty();
}

ClientDataPlaneMode WintunManager::ResolveRequestedMode() {
    const std::string env_value = ToLowerCopy(ReadEnvUtf8("DNF_PROXY_DATA_PLANE"));
    if (env_value == "wintun") {
        return ClientDataPlaneMode::ExperimentalWintun;
    }
    return ClientDataPlaneMode::LegacyTap;
}

bool WintunManager::IsExperimentalModeEnabled() {
    return ResolveRequestedMode() == ClientDataPlaneMode::ExperimentalWintun;
}

bool WintunManager::LoadRuntime(std::wstring* error_msg) {
    if (module_ != NULL) {
        return true;
    }

    module_ = LoadWintunModuleFromDisk();
    if (module_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = BuildWindowsErrorMessage(L"Unable to load wintun.dll", GetLastError());
        }
        return false;
    }

    create_adapter_ = reinterpret_cast<CreateAdapterFn>(GetProcAddress(module_, "WintunCreateAdapter"));
    open_adapter_ = reinterpret_cast<OpenAdapterFn>(GetProcAddress(module_, "WintunOpenAdapter"));
    close_adapter_ = reinterpret_cast<CloseAdapterFn>(GetProcAddress(module_, "WintunCloseAdapter"));
    get_running_driver_version_ = reinterpret_cast<GetRunningDriverVersionFn>(
        GetProcAddress(module_, "WintunGetRunningDriverVersion"));
    start_session_ = reinterpret_cast<StartSessionFn>(GetProcAddress(module_, "WintunStartSession"));
    end_session_ = reinterpret_cast<EndSessionFn>(GetProcAddress(module_, "WintunEndSession"));

    if (create_adapter_ == NULL || open_adapter_ == NULL || close_adapter_ == NULL ||
        get_running_driver_version_ == NULL || start_session_ == NULL || end_session_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = L"wintun.dll is missing required exports";
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

    adapter_ = open_adapter_(kAdapterName);
    if (adapter_ == NULL) {
        adapter_ = create_adapter_(kAdapterName, kTunnelType, NULL);
    }

    if (adapter_ == NULL) {
        if (error_msg != NULL) {
            *error_msg = BuildWindowsErrorMessage(L"Unable to open or create Wintun adapter", GetLastError());
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
            *error_msg = BuildWindowsErrorMessage(L"Unable to start Wintun session", GetLastError());
        }
        return false;
    }
    return true;
}

bool WintunManager::ConfigureAddress(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    const std::string base =
        "netsh interface ipv4 set address name=\"DNFProxyWintun\" source=static address=" +
        config.virtual_ip + " mask=" + config.subnet_mask + " gateway=" + config.gateway_ip +
        " gwmetric=1 store=active >nul 2>&1";
    int ret = ExecuteCommandSilent(base);
    if (ret == 0) {
        return true;
    }

    const std::string fallback =
        "netsh interface ip set address name=\"DNFProxyWintun\" static " +
        config.virtual_ip + " " + config.subnet_mask + " " + config.gateway_ip + " 1 >nul 2>&1";
    ret = ExecuteCommandSilent(fallback);
    if (ret != 0 && error_msg != NULL) {
        *error_msg = CommandError(L"Setting Wintun address", fallback, ret);
    }
    return ret == 0;
}

bool WintunManager::ConfigureMtu(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    if (config.mtu == 0) {
        return true;
    }

    std::ostringstream command;
    command << "netsh interface ipv4 set subinterface \"DNFProxyWintun\" mtu=" << config.mtu
            << " store=active >nul 2>&1";

    int ret = ExecuteCommandSilent(command.str());
    if (ret != 0 && error_msg != NULL) {
        *error_msg = CommandError(L"Setting Wintun MTU", command.str(), ret);
    }
    return ret == 0;
}

bool WintunManager::ConfigureRoutes(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    for (size_t i = 0; i < config.routes.size(); ++i) {
        const std::string& cidr = config.routes[i].cidr;
        std::string delete_cmd =
            "netsh interface ipv4 delete route prefix=" + cidr +
            " interface=\"DNFProxyWintun\" store=active >nul 2>&1";
        ExecuteCommandSilent(delete_cmd);

        std::string add_cmd =
            "netsh interface ipv4 add route prefix=" + cidr +
            " interface=\"DNFProxyWintun\" nexthop=" + config.gateway_ip +
            " metric=1 store=active >nul 2>&1";
        int ret = ExecuteCommandSilent(add_cmd);
        if (ret != 0) {
            if (error_msg != NULL) {
                *error_msg = CommandError(L"Adding Wintun route", add_cmd, ret);
            }
            return false;
        }
    }
    return true;
}

bool WintunManager::ConfigureInterface(const TunnelLeaseRuntimeConfig& config, std::wstring* error_msg) {
    int enable_ret = ExecuteCommandSilent("netsh interface set interface name=\"DNFProxyWintun\" enable >nul 2>&1");
    if (enable_ret != 0 && error_msg != NULL) {
        *error_msg = CommandError(L"Enabling Wintun interface", "netsh interface set interface name=\"DNFProxyWintun\" enable >nul 2>&1", enable_ret);
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
            *error_msg = L"Wintun runtime config is incomplete";
        }
        return false;
    }

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

    if (IsTruthyEnv("DNF_PROXY_WINTUN_APPLY_NETWORK")) {
        if (!ConfigureInterface(config, error_msg)) {
            Cleanup();
            return false;
        }
    }

    active_ = true;
    return true;
}

void WintunManager::ResetRuntimeState() {
    create_adapter_ = NULL;
    open_adapter_ = NULL;
    close_adapter_ = NULL;
    get_running_driver_version_ = NULL;
    start_session_ = NULL;
    end_session_ = NULL;
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
