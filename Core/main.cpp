#define _WIN32_WINNT 0x0A00 // Windows 10
#include <windows.h>

// اعلان تابع مخفی کردن DLL
bool hide_interception_dll();
#include <iostream> // Keep for logging to console/file
#include <cstdio>   // For printf
#include <cstdlib>  // For std::atexit
#include <vector>
#include <string>
#include <map>
#include <cmath> // Needed for floor(), ceil()
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <sstream> // For string stream operations
#include <iomanip> // For std::fixed and std::setprecision
#include <ctime>   // For time formatting
#include <shellapi.h> // For ShellExecute
#include <atomic> // For g_is_logging_in
#include <wininet.h> // For internet functions
#include <mmsystem.h> // For PlaySound
#include <iphlpapi.h> // For GetAdaptersInfo
#include <lmcons.h>   // For UNLEN
#include <sysinfoapi.h> // For GetSystemInfo, GlobalMemoryStatusEx
#include <VersionHelpers.h> // For IsWindows*OrGreater macros
#include <dwmapi.h> // Include dwmapi.h AFTER windows.h and _WIN32_WINNT is defined
#include <fileapi.h> // For GetVolumeInformation
#include <winuser.h> // For GetSystemMetrics
#include <timeapi.h> // For GetTickCount64
#include <dxgi.h> // For DXGI_ADAPTER_DESC and related interfaces
#include <locale.h> // For _get_user_locale / setlocale, although GetUserDefaultUILanguage is better
#include <winreg.h> // For Registry access (VM Check)
#include <winnls.h> // For Language/Locale info
#include <vector> // Needed for Base64
#include <stdint.h> // Needed for Base64 uint8_t
#include <shlobj.h> // For SHGetFolderPathA
#include <tlhelp32.h> // For CreateToolhelp32Snapshot, Process32First, Process32Next
#include <psapi.h> // For EnumProcessModules, GetModuleFileNameExA
// --- هدر و کتابخانه Interception ---
#include "interception.h" // مطمئن شوید این فایل در مسیر پروژه شما قرار دارد
#include "interception_loader.h" // هدر جدید برای بارگذاری داخلی interception.dll
#include "resource.h" // هدر منابع برای دسترسی به DLL داخلی
#include "interception_functions.h" // هدر توابع جدید برای بارگذاری داخلی interception.dll

// Forward declarations
// ... 
#pragma comment(lib, "winmm.lib") // Link against winmm.lib for PlaySound (MSVC specific)
#pragma comment(lib, "wininet.lib") // Link against wininet.lib for HTTP requests (MSVC specific)

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
                    g_boostedGammaRamp[channel][i] = (WORD)(corrected_value * 65535.0);
                    // Clamp to ensure it's within WORD range, though pow(0..1, positive_gamma) should yield 0..1
                    if (g_boostedGammaRamp[channel][i] > 0xFFFF) g_boostedGammaRamp[channel][i] = 0xFFFF;
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
static bool g_endKeyPressedLastFrame = false; // For End key state
// End Gamma Control Globals & Functions

#pragma comment(lib, "iphlpapi.lib") // Link against iphlpapi.lib for MAC address (MSVC specific)
#pragma comment(lib, "d3d11.lib") // Link against d3d11.lib (MSVC specific)
#pragma comment(lib, "dwmapi.lib") // Link against dwmapi.lib (for MSVC)
#pragma comment(lib, "dxgi.lib") // Link against dxgi.lib for GPU info

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
#pragma comment(lib, "advapi32.lib") // Link library for registry functions
#pragma comment(lib, "psapi.lib") // Link library for EnumProcessModules

#include "json.hpp" // For JSON parsing (Make sure the path is correct)
#include "picosha2.h" // Include picosha2 for hashing

// اعلان توابع مورد نیاز برای ارسال لاگ‌های امنیتی
// این اعلان‌ها باید قبل از تعریف تابع send_security_log_to_api باشند

// تابع جدید برای دریافت زمان فعلی به صورت رشته
// توابع get_current_time_string و get_mac_address قبلاً در کد تعریف شده‌اند
// بنابراین نیازی به تعریف مجدد آنها نیست

void output_log_message(const std::string& message);
std::string generate_device_id();
extern const std::string APP_VERSION_NUMBER;
std::string get_user_ip(); // اعلان تابع get_user_ip



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

// متغیرهای سراسری برای بخش اعلانات
std::string g_announcement_text = "Loading announcements...";
std::mutex g_announcement_mutex;
std::atomic<bool> g_announcement_loaded(false);
std::atomic<bool> g_announcement_fetch_initiated(false);
const char* ANNOUNCEMENT_URL = "https://script.google.com/macros/s/AKfycbzPiZF8lBgev2WudCxFOrhPS-vJPjWTkonp_XtTH8vZ29Y5noqcTaKq2LEI43Q8kN0AlA/exec";

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
        #pragma warning(disable: 4996)
        GetVersionExA((OSVERSIONINFOA*)&osInfo);
        #pragma warning(default: 4996)
        
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
        std::string device_id_hashed = generate_device_id();
        
        // دریافت IP کاربر (این عملیات ممکن است کمی زمان ببرد)
        std::string user_ip = "Unknown"; // مقدار پیش‌فرض
        try {
            user_ip = get_user_ip();
            // اگر IP نامعتبر باشد، از مقدار پیش‌فرض استفاده می‌کنیم
            if (user_ip.empty() || user_ip == "unknown_ip") {
                user_ip = "Unknown";
            }
        } catch (...) {
            // گرفتن هر نوع خطا برای اطمینان از ادامه اجرای برنامه
            output_log_message("Error getting user IP\n");
        }
        
        // لاگ کردن اطلاعات ارسالی برای دیباگ
        output_log_message("Sending security log - Device ID: " + device_id_hashed + ", IP: " + user_ip + "\n");
        
        // استفاده از توکن متن ساده برای اطمینان از عملکرد صحیح
        std::string token = "mysecrettoken"; // همونی که در Google Script تعریف کردی
        
        // URL-encode کردن پارامترها
        std::string encoded_threat_type = url_encode(security_threat_type);
        std::string encoded_details = url_encode(details);
        std::string encoded_device_id = url_encode(device_id_hashed);
        std::string encoded_ip = url_encode(user_ip);
        std::string encoded_version = url_encode(APP_VERSION_NUMBER);
        std::string encoded_token = url_encode(token);
        
        // ساختن URL بدون پارامترها - استفاده از POST به جای GET
        std::string base_api_url = "https://script.google.com/macros/s/AKfycbxaWs-NMsr3aQuAus9qSyy1h5MEDL76PNIZ-fmmxYvL2wdvZ2mpUrRnsCKIXlyt3EDyfw/exec";
        
        // ساختن پیام برای ارسال به دیسکورد
        std::string message = "Security Alert: " + encoded_threat_type + " - " + encoded_details + 
                           "\nDevice ID: " + encoded_device_id + 
                           "\nIP Address: " + encoded_ip + 
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
        return elapsedTime > 100; // مقدار آستانه را بر اساس سیستم خود تنظیم کنید
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
inline bool RunProtectionChecks() {
    // بررسی دیباگر با IsDebuggerPresent
    if (AntiDebug::CheckIsDebuggerPresent()) {
        // دیباگر شناسایی شد - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("Debugger", "IsDebuggerPresent detected a debugger");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی دیباگر راه دور با CheckRemoteDebuggerPresent
    if (AntiDebug::CheckRemoteDebuggerPresent()) {
        // دیباگر راه دور شناسایی شد - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("Debugger", "CheckRemoteDebuggerPresent detected a remote debugger");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی دیباگر با بررسی پرچم PEB
    if (AntiDebug::CheckPEBBeingDebugged()) {
        // دیباگر از طریق PEB شناسایی شد - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("Debugger", "PEB BeingDebugged flag is set");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی دیباگر با زمان‌سنجی
    if (AntiDebug::CheckExecutionTiming()) {
        // دیباگر از طریق زمان‌سنجی شناسایی شد - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("Debugger", "Abnormal execution timing detected");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی ماشین مجازی از طریق رجیستری
    if (AntiVM::CheckVMRegistry()) {
        // ماشین مجازی از طریق رجیستری شناسایی شد - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("VirtualMachine", "VM detected through registry checks");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی ماشین مجازی از طریق فرآیندها
    if (AntiVM::CheckVMProcesses()) {
        // ماشین مجازی از طریق فرآیندها شناسایی شد - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("VirtualMachine", "VM detected through process checks");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی یکپارچگی فایل اجرایی
    if (!CheckFileIntegrity()) {
        // فایل اجرایی دستکاری شده است - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("FileIntegrity", "Executable file integrity check failed");
        // سپس برنامه را می‌بندیم
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
        // زمان اجرا بیش از حد معمول است، احتمالاً دیباگ می‌شود - ابتدا لاگ ارسال می‌کنیم
        send_security_log_to_api("TimingCheck", "Abnormal operation timing detected");
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی پروسه‌های مشکوک (دیباگرها، ابزارهای مهندسی معکوس)
    if (CheckSuspiciousProcesses()) {
        // پروسه مشکوک شناسایی شد - لاگ در تابع CheckSuspiciousProcesses انجام می‌شود
        // سپس برنامه را می‌بندیم
        return true;
    }
    
    // بررسی تغییرات زمان سیستم
    if (CheckSystemTimeManipulation()) {
        // تغییر زمان سیستم شناسایی شد - لاگ در تابع CheckSystemTimeManipulation انجام می‌شود
        // سپس برنامه را می‌بندیم
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
    
    // هش‌های معتبر از پیش تعیین شده (می‌توانید چندین هش برای نسخه‌های مختلف برنامه داشته باشید)
    // این هش‌ها باید با هش فایل اجرایی اصلی مطابقت داشته باشند
    // برای امنیت بیشتر، این هش‌ها را به صورت رمزگذاری شده ذخیره کنید
    const std::vector<std::string> validHashes = {
        // هش فعلی فایل اجرایی را اینجا قرار دهید
        // مثال: "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z",
        // می‌توانید هش فایل اجرایی خود را با اجرای برنامه در حالت دیباگ و چاپ calculatedHash به دست آورید
        calculatedHash  // این خط را با هش واقعی جایگزین کنید
    };
    
    // بررسی هش محاسبه شده با لیست هش‌های معتبر
    for (const auto& hash : validHashes) {
        if (calculatedHash == hash) {
            return true;
        }
    }
    
    // اگر هش با هیچ یک از هش‌های معتبر مطابقت نداشت، فایل دستکاری شده است
    output_log_message("File integrity check failed. Calculated hash: " + calculatedHash + "\n");
    return false;
}

// بررسی زمان اجرا برای عملیات‌های حساس
inline bool CheckOperationTiming(std::function<void()> operation) {
    DWORD startTime = GetTickCount();
    
    // اجرای عملیات
    operation();
    
    DWORD endTime = GetTickCount();
    DWORD elapsedTime = endTime - startTime;
    
    // اگر زمان اجرا بیش از حد معمول باشد، احتمالاً دیباگ می‌شود
    return elapsedTime > 50; // آستانه را تنظیم کنید
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
            MessageBoxA(NULL, ("Critical system time manipulation detected: " + manipulationDetails).c_str(), 
                       "Security Alert", MB_ICONERROR | MB_OK);
            
            // بستن مستقیم برنامه فقط در صورت تغییرات بزرگ
            ExitProcess(0);
        } else {
            // برای تغییرات کوچکتر، فقط لاگ کن و هشدار بده ولی برنامه را نبند
            output_log_message("Minor time manipulation detected but allowed to continue: " + manipulationDetails + "\n");
        }
    }
    
    return isManipulated;
}

// بررسی DLL‌های تزریق شده
inline bool CheckForInjectedDLLs() {
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
        
        // DLL های مرتبط با Interception
        "interception.dll",
        "Interception.dll",
        "INTERCEPTION.DLL",
        "interseption.dll",
        "Interseption.dll",
        "INTERSEPTION.DLL",
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
        "cheatengine",
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
                    // برای اینکه برنامه کرش نکند، false برمی‌گردانیم
                    return false;
                } else {
                    // برای DLL‌های ناشناخته ولی غیرمشکوک فقط لاگ می‌گیریم و برنامه را ادامه می‌دهیم
                    send_security_log_to_api("DLL Info", "Unknown DLL detected: " + fileName + " at " + moduleName);
                    return false;
                }
            }
        }
    }
    
    return false;
}

// بررسی پروسه‌های مشکوک
inline bool CheckSuspiciousProcesses() {
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
        MessageBoxA(NULL, ("Suspicious process detected: " + foundProcess).c_str(), "Security Alert", MB_ICONERROR | MB_OK);
        
        // بستن برنامه
        ExitProcess(0);
    }
    
    return found;
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


// --- تعریف اشاره‌گرهای تابع برای توابع Interception مورد استفاده
typedef InterceptionContext (*PFN_CREATE_CONTEXT)();
typedef void (*PFN_DESTROY_CONTEXT)(InterceptionContext);
typedef InterceptionDevice (*PFN_WAIT)(InterceptionContext);
typedef int (*PFN_RECEIVE)(InterceptionContext, InterceptionDevice, InterceptionStroke*, unsigned int);
typedef int (*PFN_SEND)(InterceptionContext, InterceptionDevice, InterceptionStroke*, unsigned int);
typedef void (*PFN_SET_FILTER)(InterceptionContext, InterceptionPredicate, InterceptionFilter);
typedef int (*PFN_IS_KEYBOARD)(InterceptionDevice);
typedef int (*PFN_IS_MOUSE)(InterceptionDevice);

// متغیرهایی برای نگهداری آدرس توابع DLL
PFN_CREATE_CONTEXT interception_create_context_ptr = nullptr;
PFN_DESTROY_CONTEXT interception_destroy_context_ptr = nullptr;
PFN_WAIT interception_wait_ptr = nullptr;
PFN_RECEIVE interception_receive_ptr = nullptr;
PFN_SEND interception_send_ptr = nullptr;
PFN_SET_FILTER interception_set_filter_ptr = nullptr;
PFN_IS_KEYBOARD interception_is_keyboard_ptr = nullptr;
PFN_IS_MOUSE interception_is_mouse_ptr = nullptr;

HMODULE interception_dll_handle = nullptr;

bool loadInterceptionDLL() {
    interception_dll_handle = LoadLibrary("interception.dll");
    if (!interception_dll_handle) {
        std::cerr << "Error loading interception.dll. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // دریافت آدرس توابع - استفاده از تبدیل دوگانه برای جلوگیری از هشدارهای کامپایلر
    interception_create_context_ptr = reinterpret_cast<PFN_CREATE_CONTEXT>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_create_context")));
    interception_destroy_context_ptr = reinterpret_cast<PFN_DESTROY_CONTEXT>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_destroy_context")));
    interception_wait_ptr = reinterpret_cast<PFN_WAIT>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_wait")));
    interception_receive_ptr = reinterpret_cast<PFN_RECEIVE>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_receive")));
    interception_send_ptr = reinterpret_cast<PFN_SEND>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_send")));
    interception_set_filter_ptr = reinterpret_cast<PFN_SET_FILTER>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_set_filter")));
    interception_is_keyboard_ptr = reinterpret_cast<PFN_IS_KEYBOARD>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_is_keyboard")));
    interception_is_mouse_ptr = reinterpret_cast<PFN_IS_MOUSE>(reinterpret_cast<void*>(GetProcAddress(interception_dll_handle, "interception_is_mouse")));

    if (!interception_create_context_ptr || !interception_destroy_context_ptr || !interception_wait_ptr ||
        !interception_receive_ptr || !interception_send_ptr || !interception_set_filter_ptr ||
        !interception_is_keyboard_ptr || !interception_is_mouse_ptr) {
        std::cerr << "Error getting function addresses from interception.dll. Error code: " << GetLastError() << std::endl;
        FreeLibrary(interception_dll_handle);
        interception_dll_handle = nullptr;
        return false;
    }

    return true;
}

void unloadInterceptionDLL() {
    if (interception_dll_handle) {
        FreeLibrary(interception_dll_handle);
        interception_dll_handle = nullptr;
    }
}

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
const std::string APP_VERSION_NUMBER = "1.1.2"; // ورژن برنامه را تعریف کنید

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
const std::string PROFILE_AK47 = "AK47";
const std::string PROFILE_LR300 = "LR300";
const std::string PROFILE_THOMPSON = "THOMPSON";
const std::string PROFILE_SAR = "SAR";
const std::string PROFILE_MP5A4 = "MP5A4";
const std::string PROFILE_HMLMG = "HMLMG";
const std::string PROFILE_M249 = "M249";

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
    {PROFILE_MP5A4, VK_F8},
    {PROFILE_SAR, VK_F7},
    {PROFILE_HMLMG, VK_F9},
    {PROFILE_M249, VK_F10}
};

// Special Keybinds (UI Toggle, Exit)
std::atomic<int> g_ui_toggle_key{VK_HOME};     // Default UI Toggle key
std::atomic<int> g_exit_app_key{VK_INSERT};    // Default Exit App key
std::atomic<int> g_global_macro_toggle_key{VK_F11}; // DEPRECATED: Was for global macro toggle

// Mouse Button & Special Action Keybinds - Can be mouse buttons or keyboard keys
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

// Map for converting Interception scan codes to profile names
std::map<int, std::string> KEY_SCAN_CODE_MAP;

// State for keybind capturing in the UI
std::atomic<bool> g_is_capturing_keybind{false};
std::string g_profile_being_rebound = ""; // Which profile's keybind is being set (or special key name like "UI_TOGGLE", "EXIT_APP", "GLOBAL_MACRO_TOGGLE", "LMB", "RMB", "DOOR_UNLOCK_TRIGGER")


// --- Attachment States Structure ---
struct AttachmentState {
    bool holo = false;
    bool x8 = false;
    bool x16 = false;
    bool handmade = false;
    bool silencer = false;
    bool muzzle_boost = false; // Not all guns have this
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
};

// --- Shared State Variables ---
std::atomic<bool> profile_macro_active{false}; // Renamed from kickback_active
std::atomic<bool> ui_toggle_key_pressed{false}; // نگهداری وضعیت فشرده شدن کلید UI toggle
std::string current_gun_profile_str = "";        // Name of the currently selected profile
std::mutex profile_mutex;                        // Protects current_gun_profile_str AND calculated_profiles AND g_profile_keybinds
std::atomic<bool> left_mouse_down{false};        // State of left mouse button
std::atomic<bool> right_mouse_down{false};       // State of right mouse button
std::atomic<bool> is_crouched_interception{false}; // برای وضعیت نشسته با Interception
std::atomic<bool> stop_recoil_flag{false};       // Signal to stop current recoil spray


// --- متغیرهای Interception ---
InterceptionContext context = nullptr;
InterceptionDevice keyboard_device_id = 0;
InterceptionDevice mouse_device_id = 0;
// متغیرهای سراسری برای وضعیت نصب درایور Interception
bool g_interception_driver_installed = false; // وضعیت نصب درایور
int g_app_run_count = 0; // تعداد دفعات اجرای برنامه
bool g_system_restart_required = false; // نیاز به ریستارت سیستم
bool g_show_restart_message = false; // نمایش پیام ریستارت
std::string g_restart_message = ""; // پیام ریستارت
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

// --- Remember Me Variables ---
bool g_remember_me = false; // State of the Remember Me checkbox
std::string g_saved_license_key = ""; // To store the license key if Remember Me is checked
int g_license_used_count = -1; // To store the 'used_count' from the license API, -1 indicates not loaded

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

// تابع برای نمایش پیام بازخورد به کاربر
void show_feedback_message(const std::string& message) {
    g_feedback_message = message;
    g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // نمایش برای 3 ثانیه
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

void move_mouse_relative_interception(int dx, int dy) {
    if (dx == 0 && dy == 0) return;
    if (!context || !mouse_device_id) return;

    InterceptionMouseStroke mouse_stroke;
    mouse_stroke.x = dx;
    mouse_stroke.y = dy;
    mouse_stroke.flags = INTERCEPTION_MOUSE_MOVE_RELATIVE;
    mouse_stroke.rolling = 0;
    mouse_stroke.state = 0; // برای حرکت، state مهم نیست
    mouse_stroke.information = 0;

    interception_send_ptr(context, mouse_device_id, (InterceptionStroke*)&mouse_stroke, 1);
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
            move_mouse_relative_interception(target_dx, target_dy);
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
            move_mouse_relative_interception(move_x, move_y);
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
        move_mouse_relative_interception(final_dx, final_dy);
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
    output_log_message("Keybinds reset to defaults.\n");
}

// --- Encryption/Decryption Helpers for Remember Me ---

// IMPORTANT: CHANGE THIS KEY TO A UNIQUE, RANDOM, AND SECRET STRING FOR YOUR APPLICATION!
// This key is used for simple XOR encryption and provides only a basic level of obfuscation.
// It will NOT protect the license key from determined attackers.
const std::string XOR_KEY = "a8s7d6f9g8h0j1k2l3z4x5c6v7b8n9m0q1w2e3r4t5y6u7i8o9p0A1S2D3F4G5H6J7K8L9Z0X1C2V3B4N5M6Q7W7E8R9T0Y1U2I3O4P5";
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

// اعلان تابع get_config_path قبل از استفاده
std::string get_config_path();

// --- Config Loading/Saving ---
void load_config() {
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
        return;
    }

    nlohmann::json config_json; // Use explicit namespace
    try {
        config_file >> config_json; // Read and parse JSON from file
        config_file.close();

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
                    if (profile_attachments.contains("Silencer") && profile_attachments["Silencer"].is_boolean()) g_attachment_states[profile_name].silencer = profile_attachments["Silencer"].get<bool>();
                    if (profile_attachments.contains("MuzzleBoost") && profile_attachments["MuzzleBoost"].is_boolean()) g_attachment_states[profile_name].muzzle_boost = profile_attachments["MuzzleBoost"].get<bool>();
                    
                    // بارگذاری تنظیمات اتصالات با نام‌های کلید جدید
                    if (profile_attachments.contains("holo") && profile_attachments["holo"].is_boolean()) g_attachment_states[profile_name].holo = profile_attachments["holo"].get<bool>();
                    if (profile_attachments.contains("x8") && profile_attachments["x8"].is_boolean()) g_attachment_states[profile_name].x8 = profile_attachments["x8"].get<bool>();
                    if (profile_attachments.contains("x16") && profile_attachments["x16"].is_boolean()) g_attachment_states[profile_name].x16 = profile_attachments["x16"].get<bool>();
                    if (profile_attachments.contains("handmade") && profile_attachments["handmade"].is_boolean()) g_attachment_states[profile_name].handmade = profile_attachments["handmade"].get<bool>();
                    if (profile_attachments.contains("silencer") && profile_attachments["silencer"].is_boolean()) g_attachment_states[profile_name].silencer = profile_attachments["silencer"].get<bool>();
                    if (profile_attachments.contains("muzzle_boost") && profile_attachments["muzzle_boost"].is_boolean()) g_attachment_states[profile_name].muzzle_boost = profile_attachments["muzzle_boost"].get<bool>();
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
            }
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

        // --- Load Interception Driver Installation Status ---
        if (config_json.contains("Interception")) {
            const auto& interception_settings = config_json["Interception"];
            if (interception_settings.contains("DriverInstalled") && interception_settings["DriverInstalled"].is_boolean()) {
                g_interception_driver_installed = interception_settings["DriverInstalled"].get<bool>();
                output_log_message("Loaded Interception driver installation status: " + std::string(g_interception_driver_installed ? "Installed" : "Not Installed") + "\n");
            }
        }

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
        // On parse error, defaults initialized earlier will be used.
    } catch (const std::exception& e) {
        std::cerr << "Warning: Error loading config.json: " << e.what() << ". Using default settings." << std::endl;
        output_log_message("Warning: Error loading config.json.\n");
        // On other errors, defaults initialized earlier will be used.
    }

    output_log_message("Initial config loaded from config.json. SENSITIVITY: " + std::to_string(SENSITIVITY) + ", FOV: " + std::to_string(FOV) + ", Base Multiplier=" + std::to_string(screenMultiplier) + ", Door Code=" + std::to_string(g_door_unlock_code) + ", Door Trigger=" + vk_code_to_string(g_door_unlock_trigger_key) + ", Sound Enabled=" + (g_sound_enabled.load() ? "true" : "false") + "\n");
}

// ایجاد مسیر کامل برای فایل config.json در پوشه Documents کاربر
std::string get_config_path() {
    char path[MAX_PATH];
    // دریافت مسیر پوشه Documents کاربر
    if (SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, path) == S_OK) {
        std::string docs_path(path);
        // ایجاد پوشه برنامه اگر وجود نداشته باشد
        std::string app_folder = docs_path + "\\TeaRCore";
        CreateDirectoryA(app_folder.c_str(), NULL);
        return app_folder + "\\config.json";
    }
    
    // اگر نتوانستیم مسیر Documents را پیدا کنیم، از مسیر اجرای برنامه استفاده می‌کنیم
    if (GetModuleFileNameA(NULL, path, MAX_PATH) != 0) {
        std::string exe_path(path);
        size_t pos = exe_path.find_last_of("\\");
        if (pos != std::string::npos) {
            return exe_path.substr(0, pos + 1) + "config.json";
        }
    }
    
    // اگر هیچ کدام از روش‌ها موفق نبود، به مسیر پیش‌فرض برمی‌گردیم
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
    std::ofstream config_file(config_path);
    if (!config_file.is_open()) {
        std::cerr << "Error: Could not open " << config_path << " for saving." << std::endl;
        output_log_message("Error: Could not save to " + config_path + "\n");
        return;
    }

    nlohmann::json config_json; // Use explicit namespace

    // --- Save General Settings ---
    config_json["Settings"]["SENSITIVITY"] = SENSITIVITY;
    config_json["Settings"]["FOV"] = FOV;
    config_json["Settings"]["SoundEnabled"] = g_sound_enabled.load();
    config_json["Settings"]["AutoCrouchScopeEnabled"] = g_auto_crouch_scope_enabled.load();
    config_json["Settings"]["AutoSaveEnabled"] = AUTO_SAVE_ENABLED; // ذخیره تنظیمات Auto Save
    
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
        config_json["Attachments"][profile_name]["Silencer"] = state.silencer;
        // Only save MuzzleBoost if the gun profile is one that uses it in the UI/logic
        const std::string& current_profile_check = profile_name;
        if (current_profile_check == PROFILE_AK47 || current_profile_check == PROFILE_LR300 || current_profile_check == PROFILE_THOMPSON || current_profile_check == PROFILE_MP5A4) {
             config_json["Attachments"][profile_name]["MuzzleBoost"] = state.muzzle_boost;
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

    // --- Save Interception Driver Installation Status ---
    config_json["Interception"]["DriverInstalled"] = g_interception_driver_installed;

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
        config_json["Attachments"][profile_name]["silencer"] = state.silencer;
        config_json["Attachments"][profile_name]["muzzle_boost"] = state.muzzle_boost;
    }
    
    // ذخیره پروفایل فعلی
    config_json["CurrentProfile"] = current_gun_profile_str;

    // Write JSON to file with pretty printing
    config_file << config_json.dump(4) << std::endl; // Use 4 spaces for indentation
    config_file.close();

    // Set the hidden attribute for the config file
    if (SetFileAttributesW(L"config.json", FILE_ATTRIBUTE_HIDDEN) != 0) {
        // Success
         output_log_message("Successfully set config.json to hidden.\n");
    } else {
        // Error handling if setting attribute fails
        DWORD error = GetLastError();
        std::cerr << "Error setting config.json attribute: " << error << std::endl;
        output_log_message("Error setting config.json attribute: " + std::to_string(error) + "\n");
    }

    output_log_message("Settings saved to config.json\n");
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

    // Use the globally calculated screenMultiplier
    double local_screen_multiplier = (screenMultiplier != 0) ? screenMultiplier : -0.01; // Fallback

    // Determine attachment multipliers based on the passed struct
    // NOTE: These multipliers are hardcoded here. For a more robust solution,
    // these should ideally be stored per-gun or in a separate structure.
    double scope_holo_mult = attachments.holo ? 1.2 : 1.0;
    double scope_8x_mult = attachments.x8 ? 6.9 : 1.0; // AK default
    double scope_16x_mult = attachments.x16 ? 13.5 : 1.0; // AK default
    double scope_handmade_mult = attachments.handmade ? 0.8 : 1.0;
    double barrel_silencer_recoil = attachments.silencer ? 0.8 : 1.0; // AK default
    double barrel_muzzle_boost_rpm = attachments.muzzle_boost ? 1.1 : 1.0; // AK default

    // Calculate the combined multiplier for recoil compensation (Multiplying all four scope multipliers)
    double effective_recoil_multiplier = scope_holo_mult * scope_8x_mult * scope_16x_mult * scope_handmade_mult * barrel_silencer_recoil;

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
         screenMultiplier = -0.03 * ((SENSITIVITY+1.1) * 3.0) * (FOV / 100.0);
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


    output_log_message("Recoil profiles recalculated.\n");
    // Mutex automatically released when lock goes out of scope
}

// --- Recoil Control Thread ---
void perform_recoil_control() {
    // Label for goto jumps from inner loops if global state changes
    check_global_state_outer:;
    // Recoil thread log removed

    // Outer loop: Continuously checks for activation conditions
    while (true) {
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

                // Apply stance multipliers
                if (!is_crouched) {
                    double current_stand_multiplier = StandMultiplier;
                    // Gun-specific adjustments (only apply if standing)
                    if (active_profile_name_local == PROFILE_AK47) {
                        current_stand_multiplier *= 1.05;
                    }

                    final_comp_x = custom_round(base_comp_x * current_stand_multiplier * 0.6); // X less affected when standing
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
                 // --- End Recoil Calculation and Movement ---

                // Recoil compensation logic
                // Add debug log here to show calculated compensation values before mouse movement
                // Recoil thread log removed

            } // End of bullet loop

            // Check if we need to exit the outer RMB-held loop
            if (exit_spray_loop_completely) {
                // Recoil thread log removed
                goto check_global_state_outer; // Jump to the very start
            }

            // If we are here, it means the spray loop was exited because LMB was released (while RMB was held)
            // The outer `while (right_mouse_down)` loop will continue, waiting for the next LMB press (Step 4).

        } // End of RMB-held loop `while (right_mouse_down.load())`

        // --- RMB was RELEASED ---
        // This part is reached when the outer while(right_mouse_down.load()) condition becomes false
        // Recoil thread log removed
        // The outer while(true) loop will then re-check global state and wait for RMB down again.

        // 6. Spray finished (completed or interrupted by LMB release)
        // No need for a separate while loop here. The outer while(right_mouse_down)
        // and the checks at the beginning of that loop will handle the state.
        // Just ensure the stop_recoil_flag is set if the spray was interrupted by LMB release.
        // The conditions inside the spray loop should have already set stop_recoil_flag
        // when LMB was released.

        // Optional: Add a small sleep here before re-checking RMB state in the outer loop
        // sleep_ms(10); // Give input thread a moment to update state consistently

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
    move_mouse_relative_interception(50, 50);
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
                 // If capturing the Door Unlock Trigger, ignore keyboard input (except UI/Exit/Global Toggle)
                 // Door Unlock Trigger must be a mouse button, handled in mouse hook
                 if (g_profile_being_rebound == "DOOR_UNLOCK_TRIGGER") {
                     // UI Toggle, Exit, and Global Toggle keys are handled below and allowed through
                     // Consume all other keyboard presses while capturing Door Unlock Trigger
                     return 1;
                 }

                 // If capturing other keybinds (weapon, UI toggle, Exit, Global Toggle, LMB, RMB)
                 // Avoid capturing modifier keys alone, or mouse buttons (mouse buttons handled in mouse hook)
                 if (vkCode != VK_SHIFT && vkCode != VK_CONTROL && vkCode != VK_MENU &&
                     vkCode != VK_LSHIFT && vkCode != VK_RSHIFT &&
                     vkCode != VK_LCONTROL && vkCode != VK_RCONTROL &&
                     vkCode != VK_LMENU && vkCode != VK_RMENU &&
                     (vkCode < VK_LBUTTON || vkCode > VK_XBUTTON2)) // Exclude mouse buttons
                 {
                     // Update the keybind based on what is being rebound
                     {
                         std::lock_guard<std::mutex> lock(profile_mutex); // Protect g_profile_keybinds
                         // LMB/RMB are handled in mouse hook capturing if a mouse button is pressed
                         // But we allow keyboard keys for LMB/RMB here if a keyboard key is pressed while capturing LMB/RMB
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
                        if (current_active_state && current_profile_name == target_profile) {
                            profile_macro_active.store(false);
                            current_gun_profile_str = "";
                            stop_recoil_flag.store(true); // Stop any ongoing spray
                            output_log_message("MACRO-OFF (Profile deselected)\n");
                        } else {
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
     // Allow ImGui to handle mouse if its window has focus? Could check io.WantCaptureMouse here
     // if (ImGui::GetCurrentContext() != nullptr && ImGui::GetIO().WantCaptureMouse) {
     //     return CallNextHookEx(mouse_hook, nCode, wParam, lParam);
     // }

    if (nCode == HC_ACTION) {
        MSLLHOOKSTRUCT* msStruct = (MSLLHOOKSTRUCT*)lParam;
        int vkCode = 0; // VK code of the mouse button event

        // Determine the VK code from the mouse message
        switch (wParam) {
            case WM_LBUTTONDOWN: case WM_LBUTTONUP:   vkCode = VK_LBUTTON; break;
            case WM_RBUTTONDOWN: case WM_RBUTTONUP:   vkCode = VK_RBUTTON; break;
            case WM_MBUTTONDOWN: case WM_MBUTTONUP:   vkCode = VK_MBUTTON; break;
            case WM_XBUTTONDOWN: case WM_XBUTTONUP:
                if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON1) vkCode = VK_XBUTTON1;
                else if (GET_XBUTTON_WPARAM(msStruct->mouseData) == XBUTTON2) vkCode = VK_XBUTTON2;
                break;
            // WM_MOUSEWHEEL and WM_MOUSEHWHEEL donنt have standard VK codes used this way
        }

        // If capturing keybinds, capture the mouse button VK code
        if (g_is_capturing_keybind.load(std::memory_order_relaxed)) {
             // If capturing the Door Unlock Trigger, ignore keyboard input (except UI/Exit/Global Toggle)
             // Door Unlock Trigger must be a mouse button, handled in mouse hook
             if (g_profile_being_rebound == "DOOR_UNLOCK_TRIGGER") {
                 if (vkCode != 0 && (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN || wParam == WM_XBUTTONDOWN)) {
                     // Update the Door Unlock Trigger keybind
                     g_door_unlock_trigger_key = vkCode;
                     output_log_message("Door Unlock Trigger Keybind set to " + vk_code_to_string(vkCode) + "\n");

                     // Reset the capturing state
                     g_is_capturing_keybind.store(false, std::memory_order_relaxed);
                     g_profile_being_rebound = ""; // Clear the profile name

                     return 1; // Consume the mouse button press
                 }
                 // Consume other mouse events (like button up or wheel) while capturing trigger
                 return 1;
             }
             // If capturing other keybinds (weapon, UI toggle, Exit, Global Toggle, LMB, RMB)
             else {
                 // Capture LMB/RMB if that's what's being rebound AND a mouse button is pressed
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
                     return 1; // Consume the mouse button press
                 }
                 // Consume other mouse events (like button up or wheel) while capturing other keybinds
                 return 1;
             }
        }


        // Normal mouse handling when not capturing (only process if licensed AND not expired AND global macro is enabled)
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
                 // Optionally consume the mouse click if you don't want it to register in the game
                 // return 1; // Consume the mouse button press
            }

            // --- Existing Recoil Trigger Logic ---
            // Get the configured VK codes for LMB and RMB
            int lmb_vk = g_lmb_key.load(std::memory_order_relaxed);
            int rmb_vk = g_rmb_key.load(std::memory_order_relaxed);
            bool auto_crouch_scope_enabled = g_auto_crouch_scope_enabled.load(std::memory_order_relaxed);

            // Check if the incoming mouse button event matches the configured LMB or RMB key
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

    // ساختن آدرس API با کلید لایسنس خام و Device ID هش شده
    std::string base_api_url = "https://script.google.com/macros/s/AKfycbz3i2k-M4kixnZGU2Ja7-H4Yau5r1rvPyiXROZR2OKbC8DbWauRsasrZVO5uaVrzx0R0Q/exec";
    // توجه: ما کلید لایسنس خام را به API ارسال می کنیم، اما Device ID هش شده است.
    // سرور API شما باید انتظار Device ID هش شده را داشته باشد و آن را با Device ID های هش شده ذخیره شده مقایسه کند.
    base_api_url += "?license=" + license_key + "&device_id=" + device_id_hashed + "&version=" + APP_VERSION_NUMBER; // پارامتر ورژن را اضافه کنید // اضافه کردن پارامترها


    HINTERNET hInternet = InternetOpen(" Core Client", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            out_error_message = "Failed to initialize WinINet.";
        }
        output_log_message("Error: InternetOpen failed.\n");
        return false;
    }

    // حالا base_api_url تعریف شده است
    HINTERNET hConnect = InternetOpenUrl(hInternet, base_api_url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            out_error_message = "Failed to connect to the license server.";
        }
        output_log_message("Error: InternetOpenUrl failed.\n");
        InternetCloseHandle(hInternet);
        return false;
    }

    std::string response_body;
    char buffer[4096];
    DWORD bytes_read = 0;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        response_body.append(buffer);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

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

            output_log_message("License is valid. Remaining time (seconds): " + std::to_string(out_duration_seconds) + "\n");
            g_isLoggedIn.store(true, std::memory_order_relaxed); // Set login status to true
            return true;

        } else { // status != "valid"
            {
                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                if (json_response.contains("message")) {
                    out_error_message = json_response["message"];
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
    bool security_threat = RunProtectionChecks();
    if (security_threat) {
        // تهدید امنیتی شناسایی شده است - لاگ قبلاً توسط RunProtectionChecks به API ارسال شده است
        // ارسال لاگ نهایی به API قبل از بستن برنامه
        std::string threat_details = "Program is terminating due to security threat in login. ";
        threat_details += "System: " + std::string(computerName) + ", User: " + std::string(username);
        threat_details += ", MAC: " + mac_address;
        send_security_log_to_api("FinalAction", threat_details);
        output_log_message("Security threat detected. Exiting...\n");
        // بستن برنامه
        ExitProcess(0);
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

        current_view = ViewState::Home;
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            login_error_message = "";
        }
        recalculate_all_profiles_threadsafe();
        // پیام لاگ شامل تاریخ شروع می‌شود
        output_log_message("License accepted via API. Script activated. Start License: " + received_start_license_local + "\n");
        play_sound_async(LOGIN_SUCCESS_SOUND_FILE); // Play success sound
    } else {
        {
            std::lock_guard<std::mutex> lock(g_login_error_mutex);
            login_error_message = api_error_message_local;
        }
        // <--- شروع تغییر: تنظیم مجدد تاریخ شروع در صورت شکست --->
        {
            std::lock_guard<std::mutex> lock(g_license_data_mutex); // قفل کردن قبل از نوشتن
            g_start_license_str = "N/A"; // بازنشانی به مقدار پیش‌فرض
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
    bool security_threat = RunProtectionChecks();
    if (security_threat) {
        // تهدید امنیتی شناسایی شده است - لاگ قبلاً توسط RunProtectionChecks به API ارسال شده است
        // ارسال لاگ نهایی به API قبل از بستن برنامه
        std::string threat_details = "Program is terminating due to security threat in free trial. ";
        threat_details += "System: " + std::string(computerName) + ", User: " + std::string(username);
        threat_details += ", MAC: " + mac_address;
        send_security_log_to_api("FinalAction", threat_details);
        output_log_message("Security threat detected in free trial. Exiting...\n");
        // بستن برنامه
        ExitProcess(0);
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
    std::string base_api_url = "https://script.google.com/macros/s/AKfycbz3i2k-M4kixnZGU2Ja7-H4Yau5r1rvPyiXROZR2OKbC8DbWauRsasrZVO5uaVrzx0R0Q/exec";
    base_api_url += "?license=&device_id=" + device_id_hashed + "&version=" + APP_VERSION_NUMBER;

    // تعریف متغیرها قبل از goto
    std::string response_body;
    DWORD bytes_read = 0;
    HINTERNET hConnect = NULL;
    HINTERNET hInternet = InternetOpen(" Core Client", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        api_error_message_local = "Failed to initialize WinINet.";
        goto fail;
    }
    hConnect = InternetOpenUrl(hInternet, base_api_url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        api_error_message_local = "Failed to connect to the server.";
        InternetCloseHandle(hInternet);
        goto fail;
    }
    char buffer[4096];
    while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        response_body.append(buffer);
    }
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (response_body.empty()) {
        api_error_message_local = "Empty response from server.";
        goto fail;
    }

    try {
        json json_response = json::parse(response_body);
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
            // موفقیت: فعال‌سازی
            {
                std::lock_guard<std::mutex> lock(g_license_data_mutex);
                is_licensed.store(true);
                g_activation_time = std::chrono::system_clock::now();
                g_subscription_duration_seconds = received_duration;
                g_start_license_str = received_start_license_local;
                g_isLoggedIn.store(true, std::memory_order_relaxed); // Set login status to true for gamma control
            }
            current_view = ViewState::Home;
            {
                std::lock_guard<std::mutex> lock(g_login_error_mutex);
                login_error_message = "";
            }
            recalculate_all_profiles_threadsafe();
            output_log_message("Free Trial accepted via API. Script activated. Start License: " + received_start_license_local + "\n");
            play_sound_async(LOGIN_SUCCESS_SOUND_FILE);
            g_is_logging_in.store(false, std::memory_order_relaxed);
            return;
        } else {
            if (json_response.contains("message")) {
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
    }
    output_log_message("Free Trial check failed via API. Error: " + api_error_message_local + "\n");
    play_sound_async(LOGIN_FAILURE_SOUND_FILE);
    g_is_logging_in.store(false, std::memory_order_relaxed);
}

// --- Cleanup Function ---
void cleanup_and_exit() {
    output_log_message("\nPerforming cleanup before exit...\n");
 

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

    // Signal recoil thread to stop if it has an exit condition
    // (Current recoil thread is an infinite loop, detach is used)
    // If you add an exit flag to the recoil thread, set it here and join.
    // For now, assuming detach is sufficient for the current infinite loop.
    // If recoil_thread_obj was stored globally and joinable, you'd join it here.
    // Since it's a local variable in main, we can't join it here easily.
    // The current detach strategy means the thread might continue briefly after main exits.
    // For a clean exit, the recoil thread *must* have an exit flag it checks.

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


// --- حلقه ورودی Interception ---
void interception_input_thread_func() {
    InterceptionDevice current_device;
    InterceptionStroke stroke; // یک استروک برای استفاده مجدد

    // پیدا کردن اولین دستگاه کیبورد و ماوس (می‌تواند بهبود یابد)
    for (InterceptionDevice i = 1; i <= 20; ++i) {
        if (interception_is_keyboard_ptr(i)) {
            keyboard_device_id = i;
            output_log_message("Keyboard device ID: " + std::to_string(i) + "\n");
            break;
        }
    }
    for (InterceptionDevice i = 1; i <= 20; ++i) {
        if (interception_is_mouse_ptr(i)) {
            mouse_device_id = i;
            output_log_message("Mouse device ID: " + std::to_string(i) + "\n");
            break;
        }
    }
    if (keyboard_device_id == 0) {
        std::cerr << "Fehler: Tastaturgerät nicht gefunden!\n";
    }
    if (mouse_device_id == 0) {
        std::cerr << "Fehler: Mausgerät nicht gefunden!\n";
    }
    //if (!keyboard_device_id || !mouse_device_id) {
    //    std::cerr << "Critical: Could not find keyboard or mouse device through Interception.\n";
    //    return;
    //}

    while (interception_receive_ptr(context, current_device = interception_wait_ptr(context), &stroke, 1) > 0) {
        bool block_event = false;

        if (interception_is_keyboard_ptr(current_device)) {
            InterceptionKeyStroke &kstroke = *reinterpret_cast<InterceptionKeyStroke*>(&stroke);

            // بررسی کلید نشسته (Left Control = Scan Code 0x1D)
            if (kstroke.code == 0x1D) { // Scan code for Left Control
                if (kstroke.state == INTERCEPTION_KEY_DOWN) {
                    is_crouched_interception.store(true);
                } else if (kstroke.state == INTERCEPTION_KEY_UP) {
                    is_crouched_interception.store(false);
                }
            }

            // بررسی کلیدهای پروفایل (فقط حالت فشرده شدن)
            if (kstroke.state == INTERCEPTION_KEY_DOWN || kstroke.state == (INTERCEPTION_KEY_DOWN | INTERCEPTION_KEY_E0)) {
                if (KEY_SCAN_CODE_MAP.count(kstroke.code)) {
                    std::string target_profile = KEY_SCAN_CODE_MAP[kstroke.code];
                    std::lock_guard<std::mutex> lock(profile_mutex);

                    if (profile_macro_active.load() && current_gun_profile_str == target_profile) {
                        profile_macro_active.store(false);
                        current_gun_profile_str = "";
                        output_log_message("MACRO-OFF\n");
                    } else {
                        profile_macro_active.store(true);
                        current_gun_profile_str = target_profile;
                        output_log_message(current_gun_profile_str + "_MACRO-ON\n");
                    }
                    block_event = true; // کلید عملکردی را بلاک کن تا به بازی نرود
                }
            }
        } else if (interception_is_mouse_ptr(current_device)) {
            InterceptionMouseStroke &mstroke = *reinterpret_cast<InterceptionMouseStroke*>(&stroke);

            if (mstroke.state & INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN) {
                left_mouse_down.store(true);
            }
            if (mstroke.state & INTERCEPTION_MOUSE_LEFT_BUTTON_UP) {
                left_mouse_down.store(false);
                stop_recoil_flag.store(true);
            }
            if (mstroke.state & INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN) {
                right_mouse_down.store(true);
            }
            if (mstroke.state & INTERCEPTION_MOUSE_RIGHT_BUTTON_UP) {
                right_mouse_down.store(false);
                stop_recoil_flag.store(true);
            }
        }

        if (!block_event) {
            interception_send_ptr(context, current_device, &stroke, 1); // ارسال مجدد رویداد اگر بلاک نشده
        }
    }
    output_log_message("Interception receive loop terminated.\n");
}
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
bool isInterceptionDriverInstalled() {
    // بررسی متغیر جهانی که هنگام بارگذاری فایل پیکربندی مقداردهی شده است
    return g_interception_driver_installed;
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

bool saveInterceptionDriverStatus(bool installed) {
    // Debug log removed
    try {
        g_interception_driver_installed = installed;
        // Debug log removed
        
        // اطمینان از وجود پوشه config
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        std::string config_dir = std::string(current_dir) + "\\config";
        
        // ایجاد پوشه config اگر وجود ندارد
        if (!std::filesystem::exists(config_dir)) {
            // Debug log removed
            std::filesystem::create_directory(config_dir);
            
            // مخفی کردن پوشه config
            DWORD attributes = GetFileAttributesA(config_dir.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                SetFileAttributesA(config_dir.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
                // Debug log removed
            }
        }
        
        // مسیر فایل config.json در پوشه config
        std::string config_path = config_dir + "\\config.json";
        
        // خواندن فایل config.json اگر وجود دارد
        nlohmann::json config_json;
        std::ifstream config_file(config_path);
        if (config_file.is_open()) {
            // Debug log removed
            config_file >> config_json;
            config_file.close();
            // Debug log removed
        } else {
            // بررسی فایل قدیمی config.json در مسیر اصلی
            std::string old_config_path = std::string(current_dir) + "\\config.json";
            std::ifstream old_config_file(old_config_path);
            if (old_config_file.is_open()) {
                // Debug log removed
                old_config_file >> config_json;
                old_config_file.close();
                
                // حذف فایل قدیمی بعد از مهاجرت
                try {
                    std::filesystem::remove(old_config_path);
                    // Debug log removed
                } catch (...) {
                    // Debug log removed
                }
            } else {
                // Debug log removed
            }
        }
        
        // بررسی ساختار JSON قبل از تغییر
        if (config_json.contains("Interception")) {
            // Debug log removed
            
            // خواندن تعداد اجراهای برنامه
            if (config_json["Interception"].contains("RunCount")) {
                g_app_run_count = config_json["Interception"]["RunCount"].get<int>();
                // Debug log removed
            }
            
            // خواندن وضعیت نمایش پیام ریستارت
            if (config_json["Interception"].contains("ShowRestartMessage")) {
                g_show_restart_message = config_json["Interception"]["ShowRestartMessage"].get<bool>();
                // Debug log removed
            } else {
                // اگر این متغیر در فایل config.json وجود ندارد، فرض می‌کنیم که اولین اجرای برنامه است
                g_show_restart_message = true;
                output_log_message("[DEBUG] Show restart message not found in config. Setting to true.\n");
            }
        } else {
            // Debug log removed
        }
        
        // افزایش شمارنده اجرا
        g_app_run_count++;
        // Debug log removed
        
        // تنظیم مقادیر جدید
        config_json["Interception"]["DriverInstalled"] = installed;
        config_json["Interception"]["RunCount"] = g_app_run_count;
        config_json["Interception"]["ShowRestartMessage"] = false; // بعد از اولین اجرا، این متغیر را غیرفعال کن

        // Debug log removed
        
        // نوشتن به فایل
        std::ofstream output_file(config_path);
        if (output_file.is_open()) {
            // Debug log removed
            output_file << config_json.dump(4) << std::endl;
            output_file.close();
            // Debug log removed
            return true;
        } else {
            // Debug log removed
            
            // روش 2: نوشتن به فایل موقت و سپس تغییر نام
            try {
                // ایجاد نام فایل موقت
                std::string temp_file = config_dir + "\\config_temp.json";
                // Debug log removed
                
                // نوشتن به فایل موقت
                std::ofstream temp_output(temp_file);
                if (temp_output.is_open()) {
                    temp_output << config_json.dump(4) << std::endl;
                    temp_output.close();
                    // Debug log removed
                    
                    // تلاش برای حذف فایل اصلی و تغییر نام فایل موقت
                    if (std::filesystem::exists(config_path)) {
                        // Debug log removed
                        std::filesystem::remove(config_path);
                    }
                    
                    // روش 3: استفاده از دستور خط برای کپی فایل
                    std::string cmd = "copy /Y \"" + temp_file + "\" \"" + config_path + "\"";
                    // Debug log removed
                    int result = system(cmd.c_str());
                    // Debug log removed
                    
                    // حذف فایل موقت
                    std::filesystem::remove(temp_file);
                    
                    // بررسی نتیجه
                    if (std::filesystem::exists(config_path)) {
                        // Debug log removed
                        return true;
                    }
                }
                // Debug log removed
            } catch (const std::exception& e) {
                // Debug log removed
            }
            
            std::cerr << "Error: Could not open config.json for saving driver installation status." << std::endl;
            return false;
        }
        
        output_file.close();
        
        // تنظیم ویژگی مخفی برای فایل پیکربندی
        if (SetFileAttributesW(L"config.json", FILE_ATTRIBUTE_HIDDEN) == 0) {
            std::cerr << "Warning: Could not set config.json to hidden." << std::endl;
        }
        
        // Debug log removed
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error saving Interception driver installation status: " << e.what() << std::endl;
        return false;
    }
}

// تعریف تابع forceDeleteFile در بالای فایل انجام شده است

// --- تابع بررسی وجود سرویس Interception ---
bool isInterceptionServiceInstalled() {
    // Debug log removed
    
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        DWORD error = GetLastError();
        // Debug log removed
        return false;
    }
    
    // Debug log removed
    SC_HANDLE service = OpenServiceW(scm, L"interception", SERVICE_QUERY_STATUS);
    bool exists = (service != NULL);
    
    if (service) {
        // Debug log removed
        CloseServiceHandle(service);
    } else {
        DWORD error = GetLastError();
        // Debug log removed
    }
    
    CloseServiceHandle(scm);
    
    // اگر سرویس وجود داشت، وضعیت را در فایل config.json به‌روزرسانی کنید
    if (exists) {
        try {
            // Debug log removed
            saveInterceptionDriverStatus(true);
            // Debug log removed
        } catch (const std::exception& e) {
            // Debug log removed
            std::cerr << "Error updating config.json: " << e.what() << std::endl;
        }
    }
    
    return exists;
}

// --- تابع نصب درایور Interception ---
bool installInterceptionDriver() {
    try {
        // ابتدا بررسی می‌کنیم که آیا سرویس Interception قبلاً نصب شده است
        if (isInterceptionServiceInstalled()) {
            output_log_message("Interception service is already installed on the system.\n");
            // به‌روزرسانی فایل config.json
            saveInterceptionDriverStatus(true);
            return true;
        }
        
        output_log_message("Installing Interception driver...\n");
        
        // مسیر فایل اجرایی نصب‌کننده درایور
        std::string installer_path = "install-interception.exe";
        
        // بررسی وجود فایل نصب‌کننده با نام‌های مختلف
        // Debug log removed
        
        // لیست نام‌های ممکن برای فایل نصبی
        std::vector<std::string> possible_installer_names = {
            "install-interception.exe",
            "installinterception.exe",
            "interception-install.exe",
            "interceptioninstall.exe"
        };
        
        bool installer_found = false;
        
        // بررسی هر یک از نام‌های ممکن
        for (const auto& name : possible_installer_names) {
            // Debug log removed
            if (std::filesystem::exists(name)) {
                installer_path = name;
                installer_found = true;
                output_log_message("[DEBUG] Found installer file: " + installer_path + "\n");
                break;
            }
        }
        
        // بررسی وجود فایل نصب‌کننده
        if (!installer_found) {
            // اگر فایل نصب‌کننده وجود نداشته باشد
            std::cerr << "Interception driver installer not found! Please make sure one of the following files exists:\n";
            for (const auto& name : possible_installer_names) {
                std::cerr << "  - " << name << "\n";
            }
            std::cerr << "\n";
            
            // Debug log removed
            
            // Debug log removed
            
            // بررسی مجدد وجود سرویس
            if (isInterceptionServiceInstalled()) {
                // Debug log removed
                return saveInterceptionDriverStatus(true);
            } else {
                // Debug log removed
                return false;
            }
        }
        
        // به دست آوردن مسیر مطلق فایل نصب‌کننده
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        std::string full_installer_path = std::string(current_dir) + "\\" + installer_path;
        
        // روش 1: استفاده از ShellExecuteEx
        SHELLEXECUTEINFOW sei;
        ZeroMemory(&sei, sizeof(sei));
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = NULL;
        sei.lpVerb = L"runas";
        
        // تبدیل مسیر به wchar_t
        wchar_t wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, full_installer_path.c_str(), -1, wpath, MAX_PATH);
        sei.lpFile = wpath;
        sei.lpParameters = L"/install";
        sei.nShow = SW_SHOW;
        
        if (!ShellExecuteExW(&sei)) {
            DWORD error = GetLastError();
            
            if (error == ERROR_CANCELLED) {
                output_log_message("Driver installation was cancelled by the user.\n");
                
                // در صورت رد کردن دسترسی ادمین، فایل config.json را حذف کن
                try {
                    char current_dir[MAX_PATH];
                    GetCurrentDirectoryA(MAX_PATH, current_dir);
                    
                    // لاگ کردن مسیر جاری برای اطمینان
                    output_log_message("[DEBUG] Current directory: " + std::string(current_dir) + "\n");
                    
                    // حذف فایل config.json در مسیر اصلی
                    std::string config_path = std::string(current_dir) + "\\config.json";
                    output_log_message("[DEBUG] Attempting to delete config.json at: " + config_path + "\n");
                    
                    // بررسی وجود فایل و لاگ کردن وضعیت
                    bool config_exists = std::filesystem::exists(config_path);
                    output_log_message("[DEBUG] config.json exists: " + std::string(config_exists ? "true" : "false") + "\n");
                    
                    if (config_exists) {
                        // بررسی ویژگی‌های فایل قبل از حذف
                        DWORD attributes = GetFileAttributesA(config_path.c_str());
                        if (attributes != INVALID_FILE_ATTRIBUTES) {
                            output_log_message("[DEBUG] config.json attributes: " + std::to_string(attributes) + "\n");
                            if (attributes & FILE_ATTRIBUTE_READONLY) {
                                output_log_message("[DEBUG] config.json is read-only, changing attributes...\n");
                                SetFileAttributesA(config_path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
                            }
                        }
                        
                        // تلاش برای حذف فایل
                        if (forceDeleteFile(config_path)) {
                            output_log_message("[DEBUG] Successfully deleted config.json after admin access denial\n");
                            // بررسی مجدد برای اطمینان از حذف
                            if (!std::filesystem::exists(config_path)) {
                                output_log_message("[DEBUG] Verified config.json is deleted\n");
                            } else {
                                output_log_message("[DEBUG] Warning: config.json still exists after deletion!\n");
                            }
                        } else {
                            output_log_message("[DEBUG] Failed to delete config.json using forceDeleteFile\n");
                            // تلاش با روش دیگر
                            std::string cmd = "del /f /q /a \"" + config_path + "\"";
                            output_log_message("[DEBUG] Trying with elevated command: " + cmd + "\n");
                            system(cmd.c_str());
                            
                            // بررسی نتیجه
                            if (!std::filesystem::exists(config_path)) {
                                output_log_message("[DEBUG] Successfully deleted config.json with elevated command\n");
                            } else {
                                output_log_message("[DEBUG] All attempts to delete config.json failed\n");
                            }
                        }
                    } else {
                        output_log_message("[DEBUG] config.json not found for deletion\n");
                    }
                    
                    // بررسی وجود پوشه config
                    std::string config_dir = std::string(current_dir) + "\\config";
                    bool config_dir_exists = std::filesystem::exists(config_dir);
                    output_log_message("[DEBUG] Config directory exists: " + std::string(config_dir_exists ? "true" : "false") + "\n");
                            
                    
                    // ایجاد فایل نشانگر برای نمایش مجدد پیام در اجرای بعدی
                    std::string show_again_flag = std::string(current_dir) + "\\SHOW_RESTART_AGAIN.txt";
                    std::ofstream flag_file(show_again_flag);
                    if (flag_file.is_open()) {
                        flag_file << "User cancelled admin access. Show restart message again next time.\n";
                        flag_file.close();
                        output_log_message("[DEBUG] Created SHOW_RESTART_AGAIN.txt to show message again next time.\n");
                        
                        // مخفی کردن فایل
                        std::wstring wflag_path = std::wstring(show_again_flag.begin(), show_again_flag.end());
                        SetFileAttributesW(wflag_path.c_str(), FILE_ATTRIBUTE_HIDDEN);
                    }
                    
                    // این بخش حذف شده است چون بالاتر انجام شده است
                } catch (const std::exception& e) {
                    output_log_message("[DEBUG] Exception while handling restart flags: " + std::string(e.what()) + "\n");
                } catch (...) {
                    output_log_message("[DEBUG] Unknown error handling restart flags.\n");
                }
            } else {
                output_log_message("ShellExecuteEx failed. Trying alternative method...\n");
                
                // روش 2: استفاده از PowerShell برای اجرای با دسترسی مدیر
                std::string ps_command = "powershell -Command \"Start-Process '" + full_installer_path + "' -ArgumentList '/install' -Verb RunAs -Wait\"";
                
                int result = system(ps_command.c_str());
                
                if (result != 0) {
                    output_log_message("PowerShell command failed. Trying direct execution...\n");
                    
                    // روش 3: اجرای مستقیم
                    std::string direct_command = "\"" + full_installer_path + "\" /install";
                    result = system(direct_command.c_str());
                    
                    if (result != 0) {
                        output_log_message("All installation methods failed.\n");
                        return false;
                    }
                }
            }
        } else {
            // به جای انتظار برای اتمام فرآیند نصب، فقط پروسه را شروع می‌کنیم
            output_log_message("Driver installation started. System restart required.\n");
            
            // بستن هندل بدون انتظار برای اتمام فرآیند
            CloseHandle(sei.hProcess);
            
            // حذف فایل نصب‌کننده پس از 3 ثانیه
            std::thread([installer_path, full_installer_path]() {
                try {
                    // انتظار برای 3 ثانیه قبل از حذف فایل
                    // Debug log removed
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    // Debug log removed
                    
                    // تلاش برای حذف فایل
                    if (DeleteFileA(installer_path.c_str())) {
                        // Debug log removed
                    } else {
                        DWORD error = GetLastError();
                        // Debug log removed
                        
                        // تلاش با std::filesystem
                        try {
                            std::filesystem::remove(installer_path);
                            // Debug log removed
                        } catch (const std::exception& e) {
                            // Debug log removed
                            
                            // تلاش با دستور خط فرمان
                            std::string cmd = "del /f /q \"" + installer_path + "\"";
                            // Debug log removed
                            system(cmd.c_str());
                            
                            // بررسی نتیجه
                            if (!std::filesystem::exists(installer_path)) {
                                // Debug log removed
                            } else {
                                // Debug log removed
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    // Debug log removed
                } catch (...) {
                    // Debug log removed
                }
            }).detach(); // اجرای ترد به صورت جدا از ترد اصلی
        }
        
        // بررسی مجدد وجود سرویس بعد از نصب
        if (isInterceptionServiceInstalled()) {
            output_log_message("Interception driver installed successfully.\n");
            
            // ذخیره وضعیت نصب در فایل پیکربندی
            bool saved = saveInterceptionDriverStatus(true);
            
            // حذف فایل نصب‌کننده پس از نصب موفق
            try {
                output_log_message("Attempting to delete installer file at: " + full_installer_path + "\n");
                
                // بدون انتظار برای آزاد شدن فایل
                
                // تلاش برای حذف فایل
                if (DeleteFileA(installer_path.c_str())) {
                    output_log_message("Installer file deleted successfully.\n");
                } else {
                    DWORD error = GetLastError();
                    output_log_message("Failed to delete installer file. Error code: " + std::to_string(error) + "\n");
                }
            } catch (const std::exception& e) {
                output_log_message("Exception while trying to delete installer file: " + std::string(e.what()) + "\n");
            }
            
            return saved;
        } else {
            // نصب انجام شده اما نیاز به ریستارت سیستم است
            output_log_message("Interception driver installation seems successful, but requires system restart.\n");
            std::cerr << "\n\n===== IMPORTANT NOTICE =====\n";
            std::cerr << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n";
            std::cerr << "Please save your work and restart your computer.\n";
            std::cerr << "After restart, run this application again.\n";
            std::cerr << "===========================\n\n";
            
            // ذخیره وضعیت نصب در فایل پیکربندی برای بررسی بعد از ریستارت
            bool saved = saveInterceptionDriverStatus(true);
            
            // کاربر نصب را قبول کرده است - بررسی وجود فایل نصبی
            output_log_message("[DEBUG] User accepted installation. Installer file will be used to determine whether to show restart message.\n");
            
            // ایجاد فایل راهنما برای ریستارت و باز کردن آن
            try {
                // مسیر کامل فایل
                char current_dir[MAX_PATH];
                GetCurrentDirectoryA(MAX_PATH, current_dir);
                std::string restart_file_path = std::string(current_dir) + "\\RESTART_REQUIRED.txt";
                
                // ایجاد فایل
                std::ofstream restart_notice(restart_file_path);
                if (restart_notice.is_open()) {
                    restart_notice << "===== IMPORTANT NOTICE =====\n\n";
                    restart_notice << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n\n";
                    restart_notice << "Please restart your computer and run this application again.\n\n";
                    restart_notice << "===========================\n";
                    restart_notice.close();
                    // باز کردن فایل با برنامه پیش‌فرض سیستم
                    ShellExecuteA(NULL, "open", restart_file_path.c_str(), NULL, NULL, SW_SHOW);
                }
            } catch (const std::exception& e) {
                output_log_message("Failed to create restart notice file: " + std::string(e.what()) + "\n");
            } catch (...) {
                output_log_message("Unknown error creating or opening restart notice file.\n");
            }
            
            return saved;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error installing Interception driver: " << e.what() << std::endl;
        output_log_message("Error installing Interception driver: " + std::string(e.what()) + "\n");
        return false;
    }
}

// --- تابع به‌روزرسانی وضعیت درایور Interception در فایل config.json ---
bool updateInterceptionDriverStatus() {
    // Debug log removed
    
    // بررسی مستقیم وجود سرویس Interception
    // Debug log removed
    bool service_installed = isInterceptionServiceInstalled();
    // Debug log removed
    
    // بررسی وضعیت فعلی در فایل config.json
    try {
        // مسیر پوشه config
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        std::string config_dir = std::string(current_dir) + "\\config";
        std::string config_path = config_dir + "\\config.json";
        
        // بررسی وجود فایل config.json در پوشه config
        bool config_file_exists = std::filesystem::exists(config_path);
        
        // اگر فایل در پوشه config وجود ندارد، بررسی فایل در مسیر اصلی
        std::string old_config_path = std::string(current_dir) + "\\config.json";
        if (!config_file_exists && std::filesystem::exists(old_config_path)) {
            config_path = old_config_path;
            config_file_exists = true;
            output_log_message("[DEBUG] Using old config.json in root directory.\n");
        }
        
        if (config_file_exists) {
            std::ifstream config_file(config_path);
            if (config_file.is_open()) {
                nlohmann::json config_json;
                config_file >> config_json;
                config_file.close();
                
                // بررسی وضعیت نصب درایور در فایل پیکربندی
                bool config_driver_installed = false;
                if (config_json.contains("Interception") && 
                    config_json["Interception"].contains("DriverInstalled") && 
                    config_json["Interception"]["DriverInstalled"].is_boolean()) {
                    config_driver_installed = config_json["Interception"]["DriverInstalled"].get<bool>();
                    output_log_message("[DEBUG] Current Interception status in config: " + std::string(config_driver_installed ? "true" : "false") + "\n");
                }
                
                // اگر درایور قبلاً نصب شده باشد، وضعیت را حفظ کن
                if (config_driver_installed) {
                    output_log_message("[DEBUG] Driver was previously marked as installed in config. Preserving this status.\n");
                    g_interception_driver_installed = true;
                    return true;
                }
            }
        }
    } catch (const std::exception& e) {
        output_log_message("[DEBUG] Error reading config file: " + std::string(e.what()) + "\n");
    }
    
    // اگر سرویس نصب شده باشد، وضعیت را به true تنظیم کن
    if (service_installed) {
        bool result = saveInterceptionDriverStatus(true);
        return result;
    } else {
        // اگر فایل RESTART_REQUIRED.txt وجود داشته باشد، احتمالاً درایور نصب شده اما نیاز به ریستارت دارد
        if (std::filesystem::exists("RESTART_REQUIRED.txt")) {
            // Debug log removed
            bool result = saveInterceptionDriverStatus(true);
            // Debug log removed
            return result;
        }
        
        // Debug log removed
        bool result = saveInterceptionDriverStatus(false);
        // Debug log removed
        return result;
    }
    }

// --- تابع بررسی و نصب درایور Interception در صورت نیاز ---
bool checkAndInstallInterceptionDriver() {
    // بررسی وجود فایل نصبی
    char current_dir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, current_dir);
    
    // Debug log removed
    
    // لیست نام‌های ممکن برای فایل نصبی
    std::vector<std::string> installer_names = {
        "install-interception.exe",
        "installinterception.exe",
        "interception-install.exe",
        "interceptioninstall.exe"
    };
    
    // بررسی وجود هر یک از فایل‌های نصبی
    bool installer_exists = false;
    std::string found_installer_path;
    
    for (const auto& name : installer_names) {
        std::string installer_path = std::string(current_dir) + "\\" + name;
        if (std::filesystem::exists(installer_path)) {
            installer_exists = true;
            found_installer_path = installer_path;
            output_log_message("[DEBUG] Found installer file: " + installer_path + "\n");
            break;
        }
    }
    
    output_log_message("[DEBUG] Installer exists: " + std::string(installer_exists ? "true" : "false") + "\n");
    
    // بررسی مستقیم وجود سرویس Interception
    if (isInterceptionServiceInstalled()) {
        output_log_message("Interception service is already installed on the system.\n");
        // به‌روزرسانی فایل config.json
        saveInterceptionDriverStatus(true);
        return true;
    }
    
    // نصب درایور
    output_log_message("Interception driver is not installed. Installing now...\n");
    return installInterceptionDriver();
}

// --- Main Function ---
int main(int, char**) {
    // --- Console window will be visible by default ---
    // To hide it completely from the start, you need to compile as a GUI application.
    // The ShowWindow(GetConsoleWindow(), SW_HIDE) call is removed.

    // شروع برنامه

    // بررسی مستقیم وضعیت سرویس Interception و به‌روزرسانی config.json
    updateInterceptionDriverStatus();
    
    // بررسی وجود فایل SHOW_RESTART_AGAIN.txt برای نمایش مجدد پنجره نصب
    char current_dir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, current_dir);
    std::string show_again_flag_path = std::string(current_dir) + "\\SHOW_RESTART_AGAIN.txt";
    bool show_install_again = std::filesystem::exists(show_again_flag_path);
    
    // اگر فایل SHOW_RESTART_AGAIN.txt وجود داشته باشد، آن را حذف کن
    if (show_install_again) {
        output_log_message("[DEBUG] Found SHOW_RESTART_AGAIN.txt. Will show installation dialog again.\n");
        try {
            forceDeleteFile(show_again_flag_path);
            output_log_message("[DEBUG] Successfully deleted SHOW_RESTART_AGAIN.txt.\n");
        } catch (...) {
            output_log_message("[DEBUG] Failed to delete SHOW_RESTART_AGAIN.txt.\n");
        }
    }
    
    // بررسی وجود فایل نصبی installinterception.exe
    std::vector<std::string> installer_names = {
        "install-interception.exe",
        "installinterception.exe",
        "interception-install.exe",
        "interceptioninstall.exe"
    };
    
    bool installer_exists = false;
    std::string found_installer_path;
    
    // بررسی وجود هر یک از فایل‌های نصبی
    for (const auto& name : installer_names) {
        std::string installer_path = std::string(current_dir) + "\\" + name;
        if (std::filesystem::exists(installer_path)) {
            installer_exists = true;
            found_installer_path = installer_path;
            output_log_message("[DEBUG] Found installer file: " + installer_path + "\n");
            break;
        }
    }
    
    output_log_message("[DEBUG] Installer exists: " + std::string(installer_exists ? "true" : "false") + "\n");
    
    // بررسی و نصب درایور Interception در اولین اجرای برنامه یا اگر کاربر قبلاً نصب را رد کرده باشد
    if (g_app_run_count <= 1 || show_install_again) {
        bool installation_result = checkAndInstallInterceptionDriver();
        if (!installation_result) {
            std::cerr << "Failed to install Interception driver. Some features may not work correctly.\n";
            output_log_message("[DEBUG] Installation failed or was cancelled.\n");
        } else {
            output_log_message("[DEBUG] Installation was successful.\n");
            
            // کاربر نصب را قبول کرده است - بررسی وجود فایل نصبی
            output_log_message("[DEBUG] Installation was successful. Will check for installer file existence.\n");
        }
        
        // بررسی مجدد وجود فایل نصبی بعد از نصب
        bool installer_still_exists = false;
        for (const auto& name : installer_names) {
            std::string installer_path = std::string(current_dir) + "\\" + name;
            if (std::filesystem::exists(installer_path)) {
                installer_still_exists = true;
                output_log_message("[DEBUG] Installer file still exists after installation: " + installer_path + "\n");
                break;
            }
        }
        output_log_message("[DEBUG] After installation - Installer exists: " + std::string(installer_still_exists ? "true" : "false") + "\n");
        
        // نمایش پیام ریستارت فقط اگر فایل نصبی وجود داشته باشد
        if (installer_still_exists) {
            std::cerr << "\n\n===== IMPORTANT NOTICE =====\n";
            std::cerr << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n";
            std::cerr << "Please restart your computer and run this application again.\n";
            std::cerr << "===========================\n\n";
            
            // ایجاد فایل راهنما برای ریستارت و باز کردن آن
            try {
                std::string restart_file_path = std::string(current_dir) + "\\RESTART_REQUIRED.txt";
                
                // ایجاد فایل
                std::ofstream restart_notice(restart_file_path);
                if (restart_notice.is_open()) {
                    restart_notice << "===== IMPORTANT NOTICE =====\n\n";
                    restart_notice << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n\n";
                    restart_notice << "Please restart your computer and run this application again.\n\n";
                    restart_notice << "===========================\n";
                    restart_notice.close();
                    output_log_message("[DEBUG] Created RESTART_REQUIRED.txt file.\n");
                    
                    // باز کردن فایل با برنامه پیش‌فرض سیستم
                    ShellExecuteA(NULL, "open", restart_file_path.c_str(), NULL, NULL, SW_SHOW);
                    output_log_message("[DEBUG] Opened RESTART_REQUIRED.txt file for user.\n");
                }
            } catch (const std::exception& e) {
                output_log_message("[DEBUG] Error creating or opening restart notice file: " + std::string(e.what()) + "\n");
            } catch (...) {
                output_log_message("[DEBUG] Unknown error creating or opening restart notice file.\n");
            }
        } else {
            output_log_message("[DEBUG] Not showing restart message because installer file does not exist.\n");
        }
    } else if (!g_interception_driver_installed && !std::filesystem::exists("RESTART_REQUIRED.txt")) {
        // اگر اولین اجرا نیست اما درایور نصب نشده و فایل RESTART_REQUIRED.txt هم وجود ندارد
        output_log_message("Driver not installed and no restart required file found. Checking Interception driver...\n");
        if (!checkAndInstallInterceptionDriver()) {
            output_log_message("Failed to install Interception driver. Some features may not work correctly.\n");
        }
    } else {
        output_log_message("Not first run or driver already installed. Skipping driver installation.\n");
    }
    
    if (!loadInterceptionDLL()) {
        std::cerr << "\n\n===== IMPORTANT NOTICE =====\n";
        std::cerr << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n";
        
        // تعریف متغیر برای تصمیم‌گیری درباره نمایش پیام ریستارت
        bool should_show_restart_message = false;
        
        // بررسی وجود فایل نصبی
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        
        // لیست نام‌های ممکن برای فایل نصبی
        std::vector<std::string> installer_names = {
            "install-interception.exe",
            "installinterception.exe",
            "interception-install.exe",
            "interceptioninstall.exe"
        };
        
        // بررسی وجود هر یک از فایل‌های نصبی
        bool installer_exists = false;
        for (const auto& name : installer_names) {
            std::string installer_path = std::string(current_dir) + "\\" + name;
            output_log_message("[DEBUG] Checking for installer file: " + installer_path + "\n");
            
            if (std::filesystem::exists(installer_path)) {
                installer_exists = true;
                output_log_message("[DEBUG] Found installer file: " + installer_path + "\n");
                break;
            }
        }
        
        // تصمیم‌گیری برای نمایش پیام ریستارت
        if (installer_exists) {
            output_log_message("[DEBUG] Installer file exists. Will show restart message.\n");
            should_show_restart_message = true;
        } else {
            output_log_message("[DEBUG] No installer file found. Will NOT show restart message.\n");
            should_show_restart_message = false;
        }
        // شرط 2: اگر فایل SHOW_RESTART_AGAIN.txt وجود داشته باشد
        std::string show_again_flag_path = std::string(current_dir) + "\\SHOW_RESTART_AGAIN.txt";
        if (std::filesystem::exists(show_again_flag_path)) {
            output_log_message("[DEBUG] Found SHOW_RESTART_AGAIN.txt. Will show restart message.\n");
            should_show_restart_message = true;
            
            // حذف فایل بعد از خواندن
            try {
                forceDeleteFile(show_again_flag_path);
                output_log_message("[DEBUG] Successfully deleted SHOW_RESTART_AGAIN.txt.\n");
            } catch (...) {
                output_log_message("[DEBUG] Failed to delete SHOW_RESTART_AGAIN.txt.\n");
            }
        }
        
        // نمایش پیام ریستارت اگر شرایط برقرار باشد
        if (should_show_restart_message) {
            output_log_message("[DEBUG] Showing restart message. Conditions met.\n");
            
            // ایجاد فایل راهنما برای ریستارت و باز کردن آن
            try {
                // مسیر کامل فایل
                std::string restart_file_path = std::string(current_dir) + "\\RESTART_REQUIRED.txt";
                
                // ایجاد فایل
                std::ofstream restart_notice(restart_file_path);
                if (restart_notice.is_open()) {
                    restart_notice << "===== IMPORTANT NOTICE =====\n\n";
                    restart_notice << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n\n";
                    restart_notice << "Please restart your computer and run this application again.\n\n";
                    restart_notice << "===========================\n";
                    restart_notice.close();
                    output_log_message("[DEBUG] Created RESTART_REQUIRED.txt file.\n");
                    
                    // مخفی کردن فایل
                    std::wstring wrestart_path = std::wstring(restart_file_path.begin(), restart_file_path.end());
                    SetFileAttributesW(wrestart_path.c_str(), FILE_ATTRIBUTE_HIDDEN);
                    output_log_message("[DEBUG] RESTART_REQUIRED.txt file is now hidden.\n");
                    
                    // نمایش پیام در کنسول
                    std::cerr << "\n\n===== IMPORTANT NOTICE =====\n";
                    std::cerr << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n";
                    std::cerr << "Please restart your computer and run this application again.\n";
                    std::cerr << "===========================\n\n";
                    
                    // باز کردن فایل با برنامه پیش‌فرض سیستم
                    ShellExecuteA(NULL, "open", restart_file_path.c_str(), NULL, NULL, SW_SHOW);
                    output_log_message("[DEBUG] Opened RESTART_REQUIRED.txt file for user.\n");
                }
            } catch (const std::exception& e) {
                output_log_message("[DEBUG] Error creating or opening restart notice file: " + std::string(e.what()) + "\n");
            } catch (...) {
                output_log_message("[DEBUG] Unknown error creating or opening restart notice file.\n");
            }
        } else {
            output_log_message("[DEBUG] Skipping restart message. Conditions not met.\n");
        }    
        system("pause");
        return 1;
    }

    context = interception_create_context_ptr();
    if (!context) {
        std::cerr << "Failed to create Interception context. Some features will be limited.\n";
        output_log_message("Failed to create Interception context. Some features will be limited.\n");
        output_log_message("WARNING: The program will continue without Interception driver. Mouse control features will not work.\n");
        
        // اگر نصب انجام شده اما ریستارت نشده، اطلاع بده
        if (g_interception_driver_installed) {
            std::cerr << "\n\n===== IMPORTANT NOTICE =====\n";
            std::cerr << "Interception driver is marked as installed in config, but cannot be initialized.\n";
            std::cerr << "This usually means you need to RESTART YOUR COMPUTER to complete the installation.\n";
            std::cerr << "Please save your work and restart your computer.\n";
            std::cerr << "===========================\n\n";
            
            // ایجاد فایل راهنما برای ریستارت
            try {
                std::ofstream restart_notice("RESTART_REQUIRED.txt");
                if (restart_notice.is_open()) {
                    restart_notice << "Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.\n";
                    restart_notice << "Please restart your computer and run this application again.\n";
                    restart_notice.close();
                }
            } catch (...) {
                // اگر نتوانستیم فایل را ایجاد کنیم، ادامه می‌دهیم
            }
        }
        
        // ادامه اجرای برنامه بدون Interception
    }

    // فیلتر کردن همه دستگاه‌ها. می‌توان دقیق‌تر انتخاب کرد.
    interception_set_filter_ptr(context, (InterceptionPredicate)interception_is_keyboard_ptr, INTERCEPTION_FILTER_KEY_ALL);
    interception_set_filter_ptr(context, (InterceptionPredicate)interception_is_mouse_ptr, INTERCEPTION_FILTER_MOUSE_ALL);

    // --- Main Interception Logic and Thread Management ---
    try {
        // Note: calculate_all_profiles might depend on global config variables (SENSITIVITY, FOV, etc.)
        // Ensure these are loaded from config BEFORE calling this.
        // You also need to decide where/how calculate_all_profiles should be called initially and upon config changes.
        // For now, I'm placing it here as it was in the original main1.cpp block.
        // If calculate_all_profiles uses the new AttachmentState struct, you'll need to ensure
        // g_attachment_states is initialized or loaded from config before this call.
        recalculate_all_profiles_threadsafe(); // Changed from calculate_all_profiles()

        // Start the Interception input worker thread
        output_log_message("Attempting to start Interception input worker thread...\n");
        std::thread interception_worker_thread(interception_input_thread_func);
        interception_worker_thread.detach(); // Detach as per existing recoil thread logic
        output_log_message("Interception input worker thread started.\n");

        // Start the recoil control thread
        output_log_message("Attempting to start recoil thread...\n");
        std::thread recoil_thr(perform_recoil_control);
        output_log_message("Recoil control thread started.\n");
        recoil_thr.detach(); // جدا کردن thread لگد از thread اصلی

        std::cout << "\nScript is active..." << std::endl;

        // Note: The original main1.cpp code waited for threads to join here.
        // In a GUI application (which main.cpp seems to be), joining these threads
        // in the main UI thread will block the UI. You might need a different approach
        // for thread management (e.g., detaching threads or managing their lifecycle
        // in a way that doesn't block the main loop).
        // For now, I'm including the join calls as they were in your provided code.

        if (interception_worker_thread.joinable()) {
            interception_worker_thread.detach(); // منتظر ماندن برای نخ ورودی (معمولاً تا بسته شدن برنامه) - این خط برنامه اصلی را متوقف می‌کند تا این نخ تمام شود
        }
        if (recoil_thr.joinable()) { // اگر نخ ورودی تمام شد، این هم باید متوقف شود
            // Note: kickback_active and stop_recoil_flag might need to be set
            // before joining if you want to signal the threads to stop gracefully.
            // The original code set these flags here, assuming the input thread finishing
            // was the signal. Adjust if your application exit logic is different.
            // kickback_active.store(false); // غیرفعال کردن ماکرو
            // stop_recoil_flag.store(true); // درخواست توقف
            recoil_thr.detach(); // این خط برنامه اصلی را متوقف می‌کند تا نخ لگد تمام شود
        }
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred in main: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "An unknown unexpected error occurred in main." << std::endl;
    }

    // Initialize Winsock (Needed for actual socket implementation later)
    // WSADATA wsaData;
    // int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    // if (iResult != 0) {
    //     output_log_message("WSAStartup failed: " + std::to_string(iResult) + "\n");
    //     // Call cleanup_and_exit on failure
    //     cleanup_and_exit(); // Call cleanup before returning
    //     return 1;
    // }
    // output_log_message("Winsock initialized.\n");

    // Initialize VK code name mappings
    initialize_vk_code_names();
    output_log_message("VK code name mappings initialized.\n");

    // 1. Load initial config (incl. attachment states, keybinds, and Remember Me state/key)
    output_log_message("Attempting to load config...\n");
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
        
        // متغیرهای سراسری برای تنظیمات صدا و ذخیره خودکار
        // استفاده از std::atomic برای اطمینان از تغییرات اتمیک بین تردها
        // این متغیرها باید با استفاده از متدهای store/load خوانده و نوشته شوند
        std::atomic<bool> g_sound_enabled{true}; // به طور پیش‌فرض صدا فعال است
        // متغیر برای ذخیره خودکار تنظیمات
        bool AUTO_SAVE_ENABLED = true; // به طور پیش‌فرض ذخیره خودکار فعال است
        
        // برای اطمینان از عملکرد صحیح، از توکن متن ساده استفاده می‌کنیم
        std::string token = "mysecrettoken"; // همونی که در Google Script تعریف کردی
        
        // بعداً می‌توانیم رمزگذاری را دوباره فعال کنیم:
        /*
        // توکن رمزگذاری شده - این رشته در تحلیل استاتیک قابل خواندن نیست
        // رمزگذاری شده با کلید "security_key"
{{ ... }}
        const char encrypted_token[] = { 10, 31, 19, 13, 4, 8, 11, 4, 25, 25, 14, 6, 4, 13 }; // "mysecrettoken" رمزگذاری شده
        std::string encrypted_token_str(encrypted_token, sizeof(encrypted_token));
        std::string token = xor_encrypt_decrypt(encrypted_token_str, "security_key"); // رمزگشایی توکن
        */
        std::string username = get_username();
        std::string computer_name = get_computer_name();
        std::string mac_address = get_mac_address();
        std::string gpu_info = get_gpu_info();
        std::string system_language = get_system_language();
        std::string ram_info = get_ram_info();
        std::string cpu_info = get_cpu_info();
        std::string device_id = generate_device_id();
        std::string system_uptime = get_system_uptime();
        
        // دریافت IP کاربر (این عملیات ممکن است کمی زمان ببرد)
        std::string user_ip = get_user_ip();
        output_log_message("Retrieved user IP: " + user_ip + "\n");
        
        std::string msg = "User: " + username + 
                         "\nComputer: " + computer_name + 
                         "\nMAC: " + mac_address + 
                         "\nIP Address: " + user_ip + 
                         "\nGPU: " + gpu_info + 
                         "\nSystem Language: " + system_language + 
                         "\nTotal RAM: " + ram_info + 
                         "\nCPU Info: " + cpu_info + 
                         "\nApp Version: " + APP_VERSION_NUMBER + 
                         "\nDevice ID (Hashed): " + device_id + 
                         "\nSystem Uptime: " + system_uptime;

        send_webhook_via_google_script(webhook_url, token, msg);
    });
    webhook_thread.detach(); // Detach the thread


    // 2. Create Win32 Window
    output_log_message("Attempting to register window class...\n");
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "TeaR Core", NULL }; // Changed window title
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
        if (!mouse_hook) { throw std::runtime_error("Failed to install mouse hook!"); }
        output_log_message("Mouse listener started.\n");
        
        // بررسی وجود فایل RESTART_REQUIRED.txt برای نمایش پیام در صفحه لاگین
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        std::string restart_file_path = std::string(current_dir) + "\\RESTART_REQUIRED.txt";
        
        // بررسی وجود فایل نصبی برای تعیین نیاز به ریستارت
        bool installer_exists = false;
        
        // لیست نام‌های ممکن برای فایل نصبی
        std::vector<std::string> installer_names = {
            "install-interception.exe",
            "installinterception.exe",
            "interception-install.exe",
            "interceptioninstall.exe"
        };
        
        // بررسی وجود هر یک از فایل‌های نصبی
        for (const auto& name : installer_names) {
            std::string installer_path = std::string(current_dir) + "\\" + name;
            if (std::filesystem::exists(installer_path)) {
                installer_exists = true;
                output_log_message("[DEBUG] Found installer file: " + installer_path + "\n");
                break;
            }
        }
        
        // Debug log removed
        
        // فقط در صورتی که فایل نصبی وجود داشته باشد و درایور نصب نشده باشد، نیاز به ریستارت داریم
        bool restart_required = installer_exists && !g_interception_driver_installed;
        
        // بررسی وجود فایل SHOW_RESTART_AGAIN.txt که نشان می‌دهد کاربر در اجرای قبلی دسترسی ادمین را رد کرده است
        std::string show_again_flag_path = std::string(current_dir) + "\\SHOW_RESTART_AGAIN.txt";
        if (std::filesystem::exists(show_again_flag_path)) {
            // Debug log removed
            restart_required = true;
            g_show_restart_message = true; // مستقیماً متغیر نمایش پیام را تنظیم می‌کنیم
            
            // حذف فایل بعد از خواندن
            try {
                // Debug log removed
                
                // استفاده از تابع forceDeleteFile برای حذف قطعی فایل
                if (forceDeleteFile(show_again_flag_path)) {
                    // Debug log removed
                } else {
                    // Debug log removed
                }
            } catch (const std::exception& e) {
                // Debug log removed
            } catch (...) {
                // Debug log removed
            }
        }
        
        // اگر فایل نصبی وجود نداشته باشد و فایل RESTART_REQUIRED.txt وجود داشته باشد، فایل RESTART_REQUIRED.txt را حذف کن
        if (!installer_exists && std::filesystem::exists(restart_file_path)) {
            // Debug log removed
            try {
                if (forceDeleteFile(restart_file_path)) {
                    // Debug log removed
                } else {
                    // Debug log removed
                }
            } catch (const std::exception& e) {
                // Debug log removed
            } catch (...) {
                // Debug log removed
            }
        }
        // اگر فایل RESTART_REQUIRED.txt وجود داشته باشد، نیاز به ریستارت داریم
        else if (std::filesystem::exists(restart_file_path)) {
            restart_required = true;
            
            // مخفی کردن فایل RESTART_REQUIRED.txt
            try {
                std::wstring wrestart_path = std::wstring(restart_file_path.begin(), restart_file_path.end());
                SetFileAttributesW(wrestart_path.c_str(), FILE_ATTRIBUTE_HIDDEN);
                output_log_message("[DEBUG] RESTART_REQUIRED.txt file is now hidden.\n");
            } catch (...) {
                // Debug log removed
            }
        }
        
        // Debug log removed
        
        std::string config_dir = std::string(current_dir) + "\\config";
        // اگر پوشه config وجود ندارد، آن را ایجاد کن
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
        // اگر فایل نصبی وجود نداشته باشد، فرض می‌کنیم که پیام ریستارت قبلاً نمایش داده نشده است
        bool restart_already_shown = !installer_exists;
        
        // تنظیم متغیر سراسری برای نمایش پیام در رابط کاربری ImGui
        g_system_restart_required = restart_required;
        
        // اگر فایل پرچم وجود ندارد یا فایل SHOW_RESTART_AGAIN.txt وجود دارد، پیام ریستارت را نمایش بده
        // اگر g_show_restart_message قبلاً true شده باشد (توسط فایل SHOW_RESTART_AGAIN.txt)، به همان صورت باقی می‌ماند
        if ((!restart_already_shown && restart_required) || g_show_restart_message) {
            g_show_restart_message = true;
            output_log_message("[DEBUG] Restart message will be shown.\n");
                        
            // اطمینان از وجود پوشه config
            try {
                if (!std::filesystem::exists(config_dir)) {
                    std::filesystem::create_directory(config_dir);
                    output_log_message("[DEBUG] Created config directory.\n");
                    // مخفی کردن پوشه config
                    SetFileAttributesW(L"config", FILE_ATTRIBUTE_HIDDEN);
                }
            } catch (const std::exception& e) {
                output_log_message("[DEBUG] Error creating config directory: " + std::string(e.what()) + "\n");
            } catch (...) {
                output_log_message("[DEBUG] Unknown error creating config directory.\n");
            }
        } else {
            g_show_restart_message = false;
            if (restart_already_shown) {
                output_log_message("[DEBUG] Restart message already shown before. Will not show it again.\n");
            } else {
                output_log_message("[DEBUG] No restart required. Will not show restart message.\n");
            }
        }
        
        output_log_message("\nUI Window Ready.\n");
        

    } catch (const std::exception& e) {
        // Basic cleanup on initialization error
        std::cerr << "Initialization error: " + std::string(e.what()) << std::endl;
        output_log_message("Initialization error: " + std::string(e.what()) + "\n");
        // if (keyboard_hook) UnhookWindowsHookEx(keyboard_hook); // Cleanup happens in cleanup_and_exit
        // if (mouse_hook) UnhookWindowsHookEx(mouse_hook); // Cleanup happens in cleanup_and_exit
        if (recoil_thread_obj.joinable()) recoil_thread_obj.detach(); // Detach if started but failed later
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
                  
                  // نمایش پیام ریستارت در پایین صفحه لاگین اگر نیاز باشد و فقط در اولین اجرای برنامه
                   if (g_system_restart_required && g_show_restart_message) {
                       ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255)); // رنگ قرمز برای هشدار
                       ImGui::TextWrapped("===== IMPORTANT NOTICE =====");
                       ImGui::TextWrapped("Interception driver has been installed, but requires a SYSTEM RESTART to complete installation.");
                       ImGui::TextWrapped("Please restart your computer and run this application again.");
                       ImGui::TextWrapped("===========================");
                       ImGui::PopStyleColor();
                       
                       // دکمه ریست سیستم زیر پیام ریستارت
                       ImGui::Spacing(); // اضافه کردن فاصله
                       
                       // استایل دکمه ریست (قرمز برای هشدار)
                       ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f)); // رنگ قرمز
                       ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f)); // قرمز روشن‌تر برای هاور
                       ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f)); // قرمز روشن‌تر برای کلیک
                       
                       // دکمه ریست با اندازه کوچکتر
                       float button_width = ImGui::GetWindowWidth() * 0.3f; // 30% عرض پنجره
                       ImGui::SetCursorPosX((ImGui::GetWindowWidth() - button_width) * 0.5f); // وسط چین کردن دکمه
                       
                       if (ImGui::Button("Restart System", ImVec2(button_width, 30))) { // ارتفاع کمتر (30 پیکسل)
                           // اجرای دستور ریست سیستم
                           system("shutdown /r /t 5 /c \"Restarting system for driver installation...\" /f");
                       }
                      ImGui::PopStyleColor(3); // برگرداندن استایل‌ها
                      
                      ImGui::Separator();
                  }


            } else { // User is licensed AND valid, show the main content based on current_view
                if (current_view == ViewState::Home) {
                    // --- Home View Content ---
                    // Status Display
                    bool status_profile_active; std::string status_profile;
                    bool ui_toggle_status;
                    { std::lock_guard<std::mutex> lock(profile_mutex);
                      status_profile_active = profile_macro_active.load(std::memory_order_relaxed); // Use renamed variable
                      ui_toggle_status = ui_toggle_key_pressed.load(std::memory_order_relaxed); // وضعیت کلید UI toggle
                      status_profile = current_gun_profile_str; }
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
                            if (state.silencer) barrel_attachment = "Silencer";
                            
                            // بررسی MuzzleBoost فقط برای اسلحه‌های خاص
                            const std::string& current_profile_check = status_profile; // Use a local copy for checks
                            if (current_profile_check == PROFILE_AK47 || current_profile_check == PROFILE_LR300 || current_profile_check == PROFILE_THOMPSON || current_profile_check == PROFILE_MP5A4) {
                                if (state.muzzle_boost) barrel_attachment = "MuzzleBoost";
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
                    } else {
                        ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Inactive");
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
                        // Weapon selection changed, update the current gun profile string
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


                    // --- Attachment Toggles (Based on Selected Weapon) ---
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.0f, 1.0f)); // Orange color
                    ImGui::Text("Attachments for %s:", ALL_PROFILES[current_weapon_index].c_str());
                    ImGui::PopStyleColor(); // Revert color
                    ImGui::SameLine(); HelpMarker("Recalculates profiles automatically when changed.");

                    // Get the attachment state for the currently selected weapon
                    AttachmentState& current_attachments = g_attachment_states[ALL_PROFILES[current_weapon_index]];
                    bool attachment_changed = false; // Track if any attachment changed in this frame

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

                    if (ImGui::CollapsingHeader("Barrels")) {
                        // Barrels (assuming all guns can have these, but effects differ)
                        if (ImGui::Checkbox("Silencer", &current_attachments.silencer)) {
                            attachment_changed = true;
                        }
                        // Only show MuzzleBoost if the gun profile is one that uses it in the UI/logic
                        const std::string& selected_profile = ALL_PROFILES[current_weapon_index];
                        if (selected_profile == PROFILE_AK47 || selected_profile == PROFILE_LR300 || selected_profile == PROFILE_THOMPSON || selected_profile == PROFILE_MP5A4) {
                             if (ImGui::Checkbox("Muzzle Boost", &current_attachments.muzzle_boost)) {
                                 attachment_changed = true;
                             }
                        }
                    }

                    // Recalculate if attachments changed
                    if (attachment_changed) {
                         recalculate_all_profiles_threadsafe();
                         output_log_message("Attachments changed, profiles recalculated.\n");
                         // Set feedback message
                         g_feedback_message = "Attachments Updated!";
                         g_feedback_message_end_time = std::chrono::steady_clock::now() + std::chrono::seconds(3); // Show for 3 seconds
                         
                         // ذخیره خودکار تنظیمات اتصالات
                         if (AUTO_SAVE_ENABLED) {
                             // ذخیره تنظیمات در فایل config.json
                             save_config();
                             output_log_message("Attachment settings auto-saved.\n");
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
                        ImGui::Button("Press a key/mouse button..."); // Button text changes while capturing
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
                        ImGui::Button("Press a key/mouse button..."); // Button text changes while capturing
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
                                ImGui::Text("%s", vk_code_to_string(current_vk).c_str());
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
                                ImGui::Text("%s", vk_code_to_string(g_profile_keybinds.at(profile_name)).c_str()); // Use map lookup here
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
                    HelpMarker("When enabled, pressing right mouse button (scope) will automatically press CTRL (crouch) as well.");

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
                    ImGui::TextWrapped("Configure the door code (max 4 digits) and the mouse button to trigger the sequence.");
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
                        ImGui::Button("Press a mouse button..."); // Button text changes while capturing
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
                    ImGui::TextWrapped("Note: The Door Unlocker sequence simulates pressing 'E', moving the mouse, clicking LMB, releasing 'E', and then typing the 4-digit code.");
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
                     {

                     std::lock_guard<std::mutex> lock(g_license_data_mutex); // قفل کردن قبل از خواندن داده‌های مشترک
                         start_license_display = g_start_license_str; // خواندن تاریخ شروع
                         duration_display = g_subscription_duration_seconds; // خواندن مدت زمان
                         activation_time_display = g_activation_time; // خواندن زمان فعال‌سازی
                         local_license_used_count = g_license_used_count; // خواندن تعداد استفاده شده
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

                     // <--- شروع تغییر: نمایش تاریخ شروع لایسنس از متغیر خوانده شده --->
                     ImGui::Text("Start License Date: %s", start_license_display.c_str());
                     // <--- پایان تغییر --->

                     // Display original duration based on seconds
                     ImGui::Text("Subscription Duration: %s", format_duration_seconds(duration_display).c_str());


                     // Calculate and display remaining time
                     std::string remaining_time_str = calculate_remaining_duration_string(activation_time_display, duration_display);
                     ImGui::Text("Remaining Time: %s", remaining_time_str.c_str());

                     // نمایش تعداد استفاده شده (used_count)
                     if (local_license_used_count >= 0) {
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
                         // ImGui::SetMouseCursor(ImGuiMouseCursor_Hand); // Requires setting mouse cursor globally based on hovered item

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
                      ImGui::TextColored(ImVec4(0.0f, 1.0f, 1.0f, 1.0f), "2025-05-24"); // تاریخ آخرین به‌روزرسانی با رنگ فیروزه‌ای
                      
                      ImGui::TextWrapped("- Added Auto Crouch Scope feature");
                      ImGui::TextWrapped("- Added Restart System button");
                      ImGui::TextWrapped("- Improved button animations");
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
                      
                      ImGui::Separator();
                      
                      // Reset Button
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
                       ImGui::Separator();
                                              // Checkbox to toggle sound
                        if (ImGui::Checkbox("Enable Sounds", &sound_enabled_local)) {
                            g_sound_enabled.store(sound_enabled_local, std::memory_order_relaxed); // Update atomic state
                            // ذخیره خودکار تنظیمات در صورت فعال بودن قابلیت Auto Save
                            AutoSaveIfEnabled();
                        }
                       ImGui::SameLine(); HelpMarker("Toggle all application sounds.");
                       
                       ImGui::Separator();
                       
                       // Display current sound files (paths are hardcoded for now)
                       ImGui::Text("Exit Sound: %s", LOGIN_FAILURE_SOUND_FILE.c_str());
                       ImGui::Text("Login Success Sound: %s", LOGIN_SUCCESS_SOUND_FILE.c_str());
                       ImGui::Text("Login Failure Sound: %s", LOGIN_FAILURE_SOUND_FILE.c_str());
                       
                       ImGui::Separator();
                       
                       // --- Auto Save Settings ---
                       ImGui::Text("Auto Save Settings");
                       ImGui::Separator();
                       
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
        // --- Rendering ---
        // Only perform rendering if the window is visible
        if (show_config_window_local)
        {
            // Gamma/Brightness Toggle Logic (Night Mode)
            bool nightModeKeyCurrentlyPressed = (GetAsyncKeyState(g_nightModeKey) & 0x8000) != 0;
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
    // Call the dedicated cleanup function before the application exits
    cleanup_and_exit();

    return 0;
}
// تابع برای مخفی کردن فایل DLL در ابتدای اجرای برنامه
bool hide_interception_dll() {
    try {
        // مسیر فایل DLL در کنار برنامه
        char current_dir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_dir);
        std::string dll_path = std::string(current_dir) + "\\interception.dll";
        
        // بررسی وجود فایل DLL
        DWORD fileAttributes = GetFileAttributesA(dll_path.c_str());
        if (fileAttributes != INVALID_FILE_ATTRIBUTES) {
            // ایجاد مسیر در AppData برای ذخیره DLL
            char appDataPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath))) {
                std::string appFolder = std::string(appDataPath) + "\\CoreProgram";
                
                // ایجاد پوشه اگر وجود ندارد
                DWORD folderAttributes = GetFileAttributesA(appFolder.c_str());
                if (folderAttributes == INVALID_FILE_ATTRIBUTES) {
                    CreateDirectoryA(appFolder.c_str(), NULL);
                }
                
                // تنظیم مسیر DLL در پوشه مخفی
                std::string hidden_dll_path = appFolder + "\\interception_core.dll";
                
                // کپی فایل DLL به مسیر مخفی
                if (CopyFileA(dll_path.c_str(), hidden_dll_path.c_str(), FALSE)) {
                    std::cout << "Copied interception.dll to hidden location." << std::endl;
                    
                    // حذف فایل DLL اصلی
                    if (DeleteFileA(dll_path.c_str())) {
                        std::cout << "Successfully deleted original interception.dll." << std::endl;
                        return true;
                    } else {
                        std::cout << "Failed to delete original interception.dll." << std::endl;
                    }
                } else {
                    std::cout << "Failed to copy interception.dll to hidden location." << std::endl;
                }
            } else {
                std::cout << "Failed to get AppData path." << std::endl;
            }
        } else {
            std::cout << "interception.dll not found in application directory." << std::endl;
            // فایل وجود ندارد، احتمالاً قبلاً مخفی شده است
            return true;
        }
    } catch (const std::exception& e) {
        std::cout << "Exception while hiding interception.dll: " << e.what() << std::endl;
    } catch (...) {
        std::cout << "Unknown error while hiding interception.dll." << std::endl;
    }
    
    return false;
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

