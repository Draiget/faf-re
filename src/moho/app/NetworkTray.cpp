#include "moho/app/NetworkTray.h"

#include "moho/console/CConCommand.h"

namespace moho
{
  bool net_TrayIcon = true;

  namespace
  {
    TConVar<bool> gTConVar_net_TrayIcon(
      "net_TrayIcon",
      "1 (default): a tray icon while the game runs its own peer links (native or in-engine links), with their "
      "status, the network panel, reconnect, the log folder and diagnostics; 0 hides it.",
      &net_TrayIcon
    );
  } // namespace
} // namespace moho

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "moho/app/NetworkPanel.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/NetlinkPeers.h"

namespace moho
{
  namespace
  {
    constexpr UINT kCallbackMessage = WM_APP + 1;
    constexpr UINT kIconId = 1;
    constexpr UINT_PTR kTimerId = 1;
    constexpr UINT kTimerMs = 1000;

    constexpr UINT kCmdPanel = 1;
    constexpr UINT kCmdLogFolder = 2;
    constexpr UINT kCmdDiagnostics = 3;
    constexpr UINT kCmdReconnectFirst = 100;

    [[nodiscard]] std::wstring Wide(const std::string& text)
    {
      if (text.empty()) {
        return {};
      }
      const int n = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring out(static_cast<std::size_t>(n), L'\0');
      ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n);
      return out;
    }

    [[nodiscard]] std::string RttText(const SNetlinkPeerInfo& p)
    {
      if (p.rttMs < 0) {
        return "-";
      }
      char buf[32];
      std::snprintf(buf, sizeof(buf), "%.1f ms", p.rttMs);
      return buf;
    }

    [[nodiscard]] bool Relayed(const SNetlinkPeerInfo& p)
    {
      return p.connected && (p.localType == "relay" || p.remoteType == "relay");
    }

    // "Network (native): 2 up, 1 relayed, 1 lost": the tooltip and the menu's first line.
    [[nodiscard]] std::string StatusText(const SNetlinkSnapshot& view)
    {
      if (view.mode.empty()) {
        return "Network: the launcher's ICE adapter runs the links";
      }
      int up = 0;
      int relayed = 0;
      int lost = 0;
      for (const SNetlinkPeerInfo& p : view.peers) {
        up += p.connected ? 1 : 0;
        relayed += Relayed(p) ? 1 : 0;
        lost += p.connected ? 0 : 1;
      }
      if (view.peers.empty()) {
        return "Network (" + view.mode + "): no peers yet";
      }
      return "Network (" + view.mode + "): " + std::to_string(up) + " up, " + std::to_string(relayed) +
             " relayed, " + std::to_string(lost) + " lost";
    }

    // "&1 " .. "&9 ", then "&a " ..: a key for each peer in the Reconnect menu.
    [[nodiscard]] std::string Mnemonic(const std::size_t index)
    {
      if (index >= 9 + 26) {
        return {};
      }
      const char key = index < 9 ? static_cast<char>('1' + index) : static_cast<char>('a' + (index - 9));
      return std::string("&") + key + " ";
    }

    [[nodiscard]] std::string PeerName(const SNetlinkPeerInfo& p)
    {
      return p.login + " (" + std::to_string(p.id) + ")";
    }

    // The game's log file: `/log <file>`, as IWinApp::AppInitCommonServices opens it.
    [[nodiscard]] std::wstring LogFilePath()
    {
      fa::vector<fa::string> args;
      if (!CFG_GetArgOption("/log", 1, &args) || args.empty()) {
        return {};
      }
      const fa::string file = FILE_SuggestedExt(args[0].c_str(), "sclog");
      const std::wstring relative = Wide(std::string(file.c_str(), file.size()));
      wchar_t full[MAX_PATH * 2] = {};
      const DWORD n = ::GetFullPathNameW(relative.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
      return n > 0 && n < std::size(full) ? std::wstring(full, n) : relative;
    }

    [[nodiscard]] std::wstring ExeFolder()
    {
      wchar_t path[MAX_PATH * 2] = {};
      const DWORD n = ::GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
      std::wstring out(path, n);
      const std::size_t slash = out.find_last_of(L"\\/");
      return slash == std::wstring::npos ? out : out.substr(0, slash);
    }

    [[nodiscard]] std::string Narrow(const std::wstring& text)
    {
      const int n = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
      std::string out(static_cast<std::size_t>(n > 0 ? n - 1 : 0), '\0');
      ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, out.data(), n, nullptr, nullptr);
      return out;
    }

    // What a bug report needs: the build, every link with its counts, the log file
    // and the latest network log lines.
    [[nodiscard]] std::string DiagnosticsText(const SNetlinkSnapshot& view)
    {
      std::string out;
      out += std::string("faf-re ") + gpg::diag::BuildDescribe() + " (" + gpg::diag::BuildCommitShort() + ", " +
             gpg::diag::BuildArch() + ")\r\n";
      char when[64] = {};
      const std::time_t now = std::time(nullptr);
      std::tm local{};
      localtime_s(&local, &now);
      std::strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &local);
      out += std::string("captured ") + when + "\r\n";
      out += StatusText(view) + "\r\n";
      const std::wstring log = LogFilePath();
      if (!log.empty()) {
        out += "log file: " + Narrow(log) + "\r\n";
      }
      for (const SNetlinkPeerInfo& p : view.peers) {
        char counts[256];
        std::snprintf(
          counts, sizeof(counts), "sent %llu, received %llu, lost %llu (%.2f %%), resends %llu",
          static_cast<unsigned long long>(p.sent), static_cast<unsigned long long>(p.received),
          static_cast<unsigned long long>(p.lost), p.lossPercent, static_cast<unsigned long long>(p.resends)
        );
        out += "peer " + PeerName(p) + ": " + p.state + ", attempts " + std::to_string(p.attempts) + ", " +
               NETPANEL_PathText(p) + " (picked: " + faf::netlink::PathChoiceText(p.choice) + "), round trip " +
               RttText(p) + ", lane " +
               (p.onLane ? (p.laneEncrypted ? "encrypted" : "plain") : "off") + ", " + counts + "\r\n";
      }
      if (!view.log.empty()) {
        out += "latest network log lines:\r\n";
        for (const std::string& line : view.log) {
          out += line + "\r\n";
        }
      }
      return out;
    }

    bool CopyToClipboard(const HWND owner, const std::string& text)
    {
      const std::wstring wide = Wide(text);
      if (!::OpenClipboard(owner)) {
        return false;
      }
      bool ok = false;
      ::EmptyClipboard();
      const HGLOBAL mem = ::GlobalAlloc(GMEM_MOVEABLE, (wide.size() + 1) * sizeof(wchar_t));
      if (mem != nullptr) {
        auto* const dst = static_cast<wchar_t*>(::GlobalLock(mem));
        std::copy(wide.begin(), wide.end(), dst);
        dst[wide.size()] = L'\0';
        ::GlobalUnlock(mem);
        ok = ::SetClipboardData(CF_UNICODETEXT, mem) != nullptr;
        if (!ok) {
          ::GlobalFree(mem);
        }
      }
      ::CloseClipboard();
      return ok;
    }

    // Explorer with the log file selected (without /log, the game's own folder). The
    // shell can refuse: a game run as another user than the desktop's gets "access
    // denied". Then the path goes on the clipboard instead. Returns what happened,
    // for the panel and the log.
    std::string OpenLogFolder(const HWND owner)
    {
      const std::wstring log = LogFilePath();
      const bool haveLog = !log.empty() && ::GetFileAttributesW(log.c_str()) != INVALID_FILE_ATTRIBUTES;
      const std::wstring target = haveLog ? log : ExeFolder();
      const HRESULT com = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
      PIDLIST_ABSOLUTE item = nullptr;
      HRESULT hr = ::SHParseDisplayName(target.c_str(), nullptr, &item, 0, nullptr);
      if (SUCCEEDED(hr)) {
        // One item: its folder opens with it selected; a folder opens itself.
        hr = ::SHOpenFolderAndSelectItems(item, 0, nullptr, 0);
        ::CoTaskMemFree(item);
      }
      if (SUCCEEDED(com)) {
        ::CoUninitialize();
      }
      std::string result;
      if (SUCCEEDED(hr)) {
        result = "Log folder opened";
      } else {
        const bool copied = CopyToClipboard(owner, Narrow(target));
        char code[16];
        std::snprintf(code, sizeof(code), "0x%08lX", static_cast<unsigned long>(hr));
        result = std::string("Explorer refused (") + code + ")" +
                 (copied ? "; the log file's path is on the clipboard" : "; the log file is " + Narrow(target));
      }
      gpg::Logf("NETLINK: log folder: %s (%s)", result.c_str(), Narrow(target).c_str());
      return result;
    }

    class Tray
    {
    public:
      ~Tray() { Stop(); }

      void Start()
      {
        std::lock_guard lock(mMutex);
        if (mThread.joinable()) {
          return;
        }
        mStop = false;
        mThread = std::thread([this] { Run(); });
      }

      void Stop()
      {
        HWND hwnd = nullptr;
        {
          std::lock_guard lock(mMutex);
          if (!mThread.joinable()) {
            return;
          }
          mStop = true;
          hwnd = mHwnd;
        }
        if (hwnd != nullptr) {
          ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        mThread.join();
      }

    private:
      static LRESULT CALLBACK WndProc(const HWND hwnd, const UINT msg, const WPARAM wp, const LPARAM lp)
      {
        if (msg == WM_NCCREATE) {
          const auto* const cs = reinterpret_cast<const CREATESTRUCTW*>(lp);
          ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        }
        auto* const self = reinterpret_cast<Tray*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        return self != nullptr ? self->Handle(hwnd, msg, wp, lp) : ::DefWindowProcW(hwnd, msg, wp, lp);
      }

      LRESULT Handle(const HWND hwnd, const UINT msg, const WPARAM wp, const LPARAM lp)
      {
        if (msg == mTaskbarCreated && mTaskbarCreated != 0) {
          mShown = false; // Explorer restarted: add the icon again
          Update(hwnd);
          return 0;
        }
        switch (msg) {
        case WM_TIMER:
          Update(hwnd);
          return 0;
        case kCallbackMessage:
          if (lp == WM_LBUTTONUP || lp == WM_RBUTTONUP) {
            ShowMenu(hwnd);
          }
          return 0;
        case WM_CLOSE:
          if (mInMenu) {
            ::EndMenu(); // the menu returns, then the window goes
            mCloseAfterMenu = true;
            return 0;
          }
          ::DestroyWindow(hwnd);
          return 0;
        case WM_DESTROY:
          RemoveIcon(hwnd);
          ::KillTimer(hwnd, kTimerId);
          ::PostQuitMessage(0);
          return 0;
        default:
          return ::DefWindowProcW(hwnd, msg, wp, lp);
        }
      }

      void Run()
      {
        // ShellExecute may hand the log folder to shell extensions, which need COM.
        const HRESULT com = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        RunWindow();
        if (SUCCEEDED(com)) {
          ::CoUninitialize();
        }
      }

      void RunWindow()
      {
        const HINSTANCE instance = ::GetModuleHandleW(nullptr);
        static const wchar_t* const kClass = L"FafReNetworkTray";
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &Tray::WndProc;
        wc.hInstance = instance;
        wc.lpszClassName = kClass;
        ::RegisterClassExW(&wc); // fails harmlessly when registered by an earlier start
        mTaskbarCreated = ::RegisterWindowMessageW(L"TaskbarCreated");
        // A hidden top-level window, not a message-only one: only top-level
        // windows hear TaskbarCreated when Explorer restarts.
        const HWND hwnd = ::CreateWindowExW(0, kClass, L"faf-re network", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr,
                                            instance, this);
        if (hwnd == nullptr) {
          gpg::Logf("NETLINK: no tray icon, CreateWindowEx failed (%lu)", ::GetLastError());
          return;
        }
        {
          std::lock_guard lock(mMutex);
          mHwnd = hwnd;
          if (mStop) {
            mHwnd = nullptr;
            ::DestroyWindow(hwnd);
            return;
          }
        }
        mIcon = static_cast<HICON>(::LoadImageW(
          instance, L"IDI_WIN_FAICON", IMAGE_ICON, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), 0
        ));
        if (mIcon == nullptr) {
          mIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
        }
        ::SetTimer(hwnd, kTimerId, kTimerMs, nullptr);
        Update(hwnd);

        MSG msg;
        while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
          ::TranslateMessage(&msg);
          ::DispatchMessageW(&msg);
        }
        std::lock_guard lock(mMutex);
        mHwnd = nullptr;
      }

      void Update(const HWND hwnd)
      {
        if (!net_TrayIcon) {
          RemoveIcon(hwnd);
          return;
        }
        const std::wstring tip = Wide("faf-re " + StatusText(NETLINK_GetSnapshot()));
        if (mShown && tip == mTip) {
          return;
        }
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = hwnd;
        nid.uID = kIconId;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = kCallbackMessage;
        nid.hIcon = mIcon;
        wcsncpy_s(nid.szTip, tip.c_str(), _TRUNCATE);
        if (!mShown) {
          mShown = ::Shell_NotifyIconW(NIM_ADD, &nid) != FALSE;
          if (mShown) {
            gpg::Logf("NETLINK: tray icon shown");
          }
        } else {
          ::Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
        mTip = tip;
      }

      // A notification from the icon (a balloon, or a toast on Windows 10 and later).
      void Notify(const HWND hwnd, const std::string& title, const std::string& text)
      {
        if (!mShown) {
          return;
        }
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = hwnd;
        nid.uID = kIconId;
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        wcsncpy_s(nid.szInfoTitle, Wide(title).c_str(), _TRUNCATE);
        wcsncpy_s(nid.szInfo, Wide(text).c_str(), _TRUNCATE);
        ::Shell_NotifyIconW(NIM_MODIFY, &nid);
      }

      void RemoveIcon(const HWND hwnd)
      {
        if (!mShown) {
          return;
        }
        NOTIFYICONDATAW nid{};
        nid.cbSize = sizeof(nid);
        nid.hWnd = hwnd;
        nid.uID = kIconId;
        ::Shell_NotifyIconW(NIM_DELETE, &nid);
        mShown = false;
        mTip.clear();
        gpg::Logf("NETLINK: tray icon removed");
      }

      void ShowMenu(const HWND hwnd)
      {
        const SNetlinkSnapshot view = NETLINK_GetSnapshot();
        const HMENU menu = ::CreatePopupMenu();
        ::AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, Wide(StatusText(view)).c_str());
        for (const SNetlinkPeerInfo& p : view.peers) {
          const std::string line = "    " + PeerName(p) + ": " + p.state + ", " + NETPANEL_PathText(p) + ", " +
                                   RttText(p);
          ::AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, Wide(line).c_str());
        }
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (net_ShowPanel ? MF_CHECKED : MF_UNCHECKED), kCmdPanel,
                      L"&Network panel\tCtrl+Shift+F11");
        const HMENU reconnect = ::CreatePopupMenu();
        std::vector<std::int64_t> ids;
        for (const SNetlinkPeerInfo& p : view.peers) {
          ::AppendMenuW(reconnect, MF_STRING, kCmdReconnectFirst + static_cast<UINT>(ids.size()),
                        Wide(Mnemonic(ids.size()) + PeerName(p)).c_str());
          ids.push_back(p.id);
        }
        ::AppendMenuW(menu, MF_POPUP | (ids.empty() ? MF_GRAYED : 0u), reinterpret_cast<UINT_PTR>(reconnect),
                      L"&Reconnect");
        ::AppendMenuW(menu, MF_STRING, kCmdLogFolder, L"Open &log folder");
        ::AppendMenuW(menu, MF_STRING, kCmdDiagnostics, L"&Copy diagnostics");

        // A tray menu closes on a click elsewhere only while its window is in front.
        ::SetForegroundWindow(hwnd);
        POINT at{};
        ::GetCursorPos(&at);
        mInMenu = true;
        const UINT cmd = static_cast<UINT>(::TrackPopupMenu(
          menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, at.x, at.y, 0, hwnd, nullptr
        ));
        mInMenu = false;
        ::PostMessageW(hwnd, WM_NULL, 0, 0);
        ::DestroyMenu(menu); // and the submenu with it

        if (mCloseAfterMenu) {
          ::DestroyWindow(hwnd);
          return;
        }
        if (cmd == kCmdPanel) {
          NETPANEL_Toggle();
          gpg::Logf("NETLINK: tray: network panel %s", net_ShowPanel ? "shown" : "hidden");
        } else if (cmd == kCmdLogFolder) {
          const std::string result = OpenLogFolder(hwnd);
          if (result.rfind("Log folder opened", 0) != 0) {
            Notify(hwnd, "Log folder", result); // the tray has no panel to say it in
          }
        } else if (cmd == kCmdDiagnostics) {
          const std::string text = DiagnosticsText(NETLINK_GetSnapshot());
          const bool ok = CopyToClipboard(hwnd, text);
          gpg::Logf("NETLINK: tray: diagnostics %s (%d bytes)", ok ? "copied to the clipboard" : "not copied",
                    static_cast<int>(text.size()));
        } else if (cmd >= kCmdReconnectFirst && cmd - kCmdReconnectFirst < ids.size()) {
          const std::int64_t id = ids[cmd - kCmdReconnectFirst];
          if (!NETLINK_ReconnectPeer(id)) {
            gpg::Logf("NETLINK: tray: no link to peer %lld any more", static_cast<long long>(id));
          }
        }
      }

      std::mutex mMutex;
      std::thread mThread;
      bool mStop = false;
      HWND mHwnd = nullptr;
      // The icon's own thread only:
      UINT mTaskbarCreated = 0;
      HICON mIcon = nullptr;
      bool mShown = false;
      std::wstring mTip;
      bool mInMenu = false;
      bool mCloseAfterMenu = false;
    };

    Tray& TheTray()
    {
      static Tray tray; // its destructor removes the icon at exit
      return tray;
    }
  } // namespace

  std::string NETDIAG_OpenLogFolder(void* const owner)
  {
    return OpenLogFolder(static_cast<HWND>(owner));
  }

  std::string NETDIAG_LogFilePath()
  {
    return Narrow(LogFilePath());
  }

  std::string NETDIAG_Text()
  {
    return DiagnosticsText(NETLINK_GetSnapshot());
  }

  bool NETDIAG_CopyText(void* const owner, const std::string& text)
  {
    return CopyToClipboard(static_cast<HWND>(owner), text);
  }

  void NETTRAY_Start()
  {
    TheTray().Start();
  }

  void NETTRAY_Stop()
  {
    TheTray().Stop();
  }
} // namespace moho

#else

namespace moho
{
  void NETTRAY_Start() {}
  void NETTRAY_Stop() {}
  std::string NETDIAG_OpenLogFolder(void*)
  {
    return {};
  }
  std::string NETDIAG_LogFilePath()
  {
    return {};
  }
  std::string NETDIAG_Text()
  {
    return {};
  }
  bool NETDIAG_CopyText(void*, const std::string&)
  {
    return false;
  }
} // namespace moho

#endif
