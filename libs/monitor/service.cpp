#include "service.hpp"
#ifdef _WIN32
#include "monitor_cli.hpp"
#include "unique_handle.hpp"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include <chrono>
#include <ctime>

namespace av {
namespace {
constexpr wchar_t SERVICE_NAME[] = L"AVScanMonitor";
constexpr wchar_t REG_KEY[] = L"Software\\AVScan\\Monitor";

std::filesystem::path serviceLogPath() {
    wchar_t base[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, base)))
        return std::filesystem::path(L"avmonitor-service.log");
    std::error_code ec;
    std::filesystem::path dir = std::filesystem::path(base) / L"AVScan";
    std::filesystem::create_directories(dir, ec);
    return dir / L"monitor.log";
}

void svcLog(const std::string& s) {
    static std::mutex mu;
    std::lock_guard l(mu);
    std::ofstream f(serviceLogPath(), std::ios::app);
    if (!f) return;
    auto now = std::time(nullptr);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", std::localtime(&now));
    f << ts << ' ' << s << '\n';
}

std::wstring readServiceArgs() {
    HKEY k = nullptr;
    wchar_t buf[4096] = {};
    DWORD type = 0, size = sizeof(buf);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
        RegQueryValueExW(k, L"Args", nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size);
        RegCloseKey(k);
    }
    return buf;
}

SERVICE_STATUS_HANDLE g_status = nullptr;
std::stop_source g_stop;

void setSvcStatus(DWORD state, DWORD exit = 0, DWORD wait = 0) {
    if (!g_status) return;
    SERVICE_STATUS s{};
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwControlsAccepted = (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    s.dwWin32ExitCode = exit;
    s.dwWaitHint = wait;
    SetServiceStatus(g_status, &s);
}

DWORD WINAPI control(DWORD code, DWORD, LPVOID, LPVOID) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        setSvcStatus(SERVICE_STOP_PENDING, 0, 30000);
        g_stop.request_stop();
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI svcMain(DWORD, LPWSTR*) {
    g_status = RegisterServiceCtrlHandlerExW(SERVICE_NAME, control, nullptr);
    if (!g_status) return;
    setSvcStatus(SERVICE_START_PENDING, 0, 10000);
    try {
        // Split the configured argument string into tokens (space-separated).
        std::wstring raw = readServiceArgs();
        std::vector<std::wstring> tokens;
        std::wstring cur;
        for (wchar_t c : raw) {
            if (c == L' ' || c == L'\t') { if (!cur.empty()) { tokens.push_back(cur); cur.clear(); } }
            else cur += c;
        }
        if (!cur.empty()) tokens.push_back(cur);
        MonitorOptions o;
        parseMonitorArgs(tokens, o);
        if (o.roots.empty()) { // service default: watch common user profile dirs
            PWSTR d = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &d))) {
                o.roots.emplace_back(d); o.priority.emplace_back(d); CoTaskMemFree(d);
            }
            wchar_t temp[32768];
            DWORD n = GetTempPathW(32768, temp);
            if (n && n < 32768) { o.roots.emplace_back(temp); o.priority.emplace_back(temp); }
        }
        svcLog("service starting: roots=" + std::to_string(o.roots.size()) +
               " etw=" + (o.etw ? "1" : "0") + " blockExec=" + (o.blockExec ? "1" : "0"));
        setSvcStatus(SERVICE_RUNNING);
        auto r = monitor(o, g_stop.get_token(), [](const std::string& s) { svcLog(s); });
        svcLog(r ? "service monitor stopped cleanly" : "service monitor error: " + r.error().message);
    } catch (std::exception& e) {
        svcLog(std::string("service exception: ") + e.what());
    }
    setSvcStatus(SERVICE_STOPPED);
}
}

Result<void> installService(const std::wstring& serviceArgs) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return failure("OpenSCManager failed (run as admin)");
    struct CloseSc { SC_HANDLE h; ~CloseSc() { CloseServiceHandle(h); } } c1{scm};
    wchar_t exe[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return failure("GetModuleFileNameW failed");
    std::wstring binPath = std::wstring(L"\"") + exe + L"\" --service";
    SC_HANDLE svc = CreateServiceW(scm, SERVICE_NAME, L"AVScan Monitor",
                                   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                   binPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) return failure("CreateService failed (already installed? admin?)");
    struct CloseSvc { SC_HANDLE h; ~CloseSvc() { CloseServiceHandle(h); } } c2{svc};
    SERVICE_DESCRIPTIONW d{const_cast<LPWSTR>(L"AVScan directory monitor (IOCP/ETW real-time scanning)")};
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &d);
    auto a = setServiceArgs(serviceArgs);
    if (!a) return failure("service created but Args write failed: " + a.error().message);
    return {};
}

Result<void> removeService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return failure("OpenSCManager failed (run as admin)");
    struct CloseSc { SC_HANDLE h; ~CloseSc() { CloseServiceHandle(h); } } c1{scm};
    SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, DELETE | SERVICE_STOP);
    if (!svc) return failure("service not found");
    struct CloseSvc { SC_HANDLE h; ~CloseSvc() { CloseServiceHandle(h); } } c2{svc};
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st); // best-effort stop
    if (!DeleteService(svc)) return failure("DeleteService failed");
    return {};
}

Result<void> setServiceArgs(const std::wstring& args) {
    HKEY k = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
    if (rc != ERROR_SUCCESS) return failure("RegCreateKeyExW failed (admin?)");
    struct CloseK { HKEY h; ~CloseK() { RegCloseKey(h); } } c{k};
    rc = RegSetValueExW(k, L"Args", 0, REG_SZ, reinterpret_cast<const BYTE*>(args.c_str()),
                        DWORD((args.size() + 1) * sizeof(wchar_t)));
    if (rc != ERROR_SUCCESS) return failure("RegSetValueExW failed");
    return {};
}

int runService() {
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(SERVICE_NAME), svcMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return 2;
    return 0;
}
}
#endif
