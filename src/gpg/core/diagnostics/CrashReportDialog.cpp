// Engine addition (dedicated-server plan WPR.12): the crash dialog, the client's half of the
// crash report (CrashReport.cpp writes the report and the minidump). A window, a clipboard and
// a shell call, so it is client code: src/sim_sources.cmake leaves it out of the simulation's
// objects, and headless and the game server end without a dialog. It sets
// sCrashReportDialog during static initialisation; the client's own exception filter
// (moho/app/WinApp.cpp) calls ShowCrashReportDialog directly.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <shellapi.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

#include "gpg/core/diagnostics/CrashReport.h"

namespace gpg::diag
{
  void CopyCrashReportToClipboard()
  {
    // Read the whole report; if it is missing, still clear-ish-fail quietly.
    std::FILE* const source = std::fopen(CrashReportPath(), "rb");
    if (source == nullptr) {
      return;
    }
    (void)std::fseek(source, 0, SEEK_END);
    const long bytes = std::ftell(source);
    (void)std::fseek(source, 0, SEEK_SET);
    if (bytes <= 0 || bytes > 8 * 1024 * 1024) {
      (void)std::fclose(source);
      return;
    }

    const std::size_t textBytes = static_cast<std::size_t>(bytes);
    char* const utf8 = static_cast<char*>(::HeapAlloc(::GetProcessHeap(), 0, textBytes + 1));
    if (utf8 == nullptr) {
      (void)std::fclose(source);
      return;
    }
    const std::size_t read = std::fread(utf8, 1, textBytes, source);
    (void)std::fclose(source);
    utf8[read] = '\0';

    // UTF-8 -> UTF-16 (report text is ASCII-dominated; use the system helper
    // and fall back to a truncation when conversion fails).
    const int wideChars = ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    bool ok = false;
    if (wideChars > 0) {
      const std::size_t wideBytes = static_cast<std::size_t>(wideChars) * sizeof(wchar_t);
      // GMEM_MOVEABLE is required by CF_UNICODETEXT.
      HGLOBAL global = ::GlobalAlloc(GMEM_MOVEABLE, wideBytes);
      if (global != nullptr) {
        wchar_t* const destination = static_cast<wchar_t*>(::GlobalLock(global));
        if (destination != nullptr) {
          if (::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, destination, wideChars) != 0) {
            if (::OpenClipboard(nullptr) != FALSE) {
              if (::EmptyClipboard() != FALSE) {
                ok = ::SetClipboardData(CF_UNICODETEXT, global) != nullptr;
              }
              (void)::CloseClipboard();
            }
          }
          (void)::GlobalUnlock(global);
        }
        if (!ok) {
          (void)::GlobalFree(global);
        }
      }
    }
    (void)::HeapFree(::GetProcessHeap(), 0, utf8);
  }

  namespace
  {

    // Report text handed to the dialog (owned by ShowCrashReportDialog's
    // frame; the dialog only runs inside its DialogBoxIndirectParam call).
    wchar_t* sCrashDialogText = nullptr;
    char sCrashDialogReportPath[MAX_PATH * 2] = {};

    // Control ids for the edit and the three buttons.
    constexpr int kCopyButtonId = 1065;
    constexpr int kOpenFolderButtonId = 1066;
    constexpr int kCloseButtonId = 1067;
    constexpr int kEditControlId = 1068;

    void CreateCrashDialogChildren(HWND dialog)
    {
      HFONT font = static_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));

      // Created at dummy coordinates: the real geometry comes from
      // LayoutCrashDialogChildren, which runs right after this on the actual
      // client rect (and again on every WM_SIZE).
      HWND edit = ::CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", sCrashDialogText,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 100, 100, dialog, reinterpret_cast<HMENU>(static_cast<std::uintptr_t>(kEditControlId)),
        nullptr, nullptr
      );
      if (edit != nullptr) {
        (void)::SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        // Keep the selection at the top: the most useful lines are first.
        (void)::SendMessageW(edit, EM_SETSEL, 0, 0);
        (void)::SendMessageW(edit, EM_SCROLLCARET, 0, 0);
      }

      const wchar_t* const labels[] = {L"Copy report", L"Open report folder", L"Close"};
      const int ids[] = {kCopyButtonId, kOpenFolderButtonId, kCloseButtonId};
      for (int i = 0; i < 3; ++i) {
        HWND button = ::CreateWindowExW(
          0, L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 100, 30, dialog,
          reinterpret_cast<HMENU>(static_cast<std::uintptr_t>(ids[i])), nullptr, nullptr
        );
        if (button != nullptr) {
          (void)::SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
        }
      }
    }

    void LayoutCrashDialogChildren(HWND dialog)
    {
      RECT client{};
      if (::GetClientRect(dialog, &client) == FALSE) {
        return;
      }
      const int clientWidth = client.right - client.left;
      const int clientHeight = client.bottom - client.top;

      const int margin = 8;
      const int buttonHeight = 32;
      const int buttonWidth = 170;
      const int buttonGap = 12;

      int x = margin;
      for (int i = 0; i < 3; ++i) {
        const int id = (i == 0) ? kCopyButtonId : ((i == 1) ? kOpenFolderButtonId : kCloseButtonId);
        (void)::SetWindowPos(
          ::GetDlgItem(dialog, id), nullptr, x, clientHeight - buttonHeight - margin, buttonWidth, buttonHeight,
          SWP_NOZORDER
        );
        x += buttonWidth + buttonGap;
      }

      HWND edit = ::GetDlgItem(dialog, kEditControlId);
      if (edit != nullptr) {
        (void)::SetWindowPos(
          edit, nullptr, margin, margin, clientWidth - 2 * margin,
          clientHeight - buttonHeight - 3 * margin, SWP_NOZORDER
        );
      }
    }

    INT_PTR CALLBACK CrashReportDialogProc(HWND dialog, const UINT message, const WPARAM wParam, const LPARAM lParam)
    {
      switch (message) {
        case WM_INITDIALOG: {
          (void)lParam;

          // Size to 3/4 of the primary monitor's work area. The template's
          // 500x350 dialog units are only a fallback; the report text is
          // much longer than any fixed size.
          HMONITOR monitor = ::MonitorFromWindow(dialog, MONITOR_DEFAULTTOPRIMARY);
          MONITORINFO monitorInfo{};
          monitorInfo.cbSize = sizeof(monitorInfo);
          if (::GetMonitorInfoW(monitor, &monitorInfo) != FALSE) {
            const int width = ((monitorInfo.rcWork.right - monitorInfo.rcWork.left) * 3) / 4;
            const int height = ((monitorInfo.rcWork.bottom - monitorInfo.rcWork.top) * 3) / 4;
            const int x = monitorInfo.rcWork.left + ((monitorInfo.rcWork.right - monitorInfo.rcWork.left) - width) / 2;
            const int y =
              monitorInfo.rcWork.top + ((monitorInfo.rcWork.bottom - monitorInfo.rcWork.top) - height) / 2;
            (void)::SetWindowPos(dialog, HWND_TOP, x, y, width, height, SWP_SHOWWINDOW);
          }

          CreateCrashDialogChildren(dialog);
          // The dialog's own WM_SIZE arrived before WM_INITDIALOG (children
          // did not exist yet), so lay out once now against the real client
          // rect; every later WM_SIZE re-runs it.
          LayoutCrashDialogChildren(dialog);
          return TRUE;
        }
        case WM_SIZE:
          LayoutCrashDialogChildren(dialog);
          return TRUE;
        case WM_COMMAND: {
          const int id = LOWORD(wParam);
          if (id == kCopyButtonId) {
            CopyCrashReportToClipboard();
            ::SetDlgItemTextW(dialog, kCopyButtonId, L"Copied!");
            return TRUE;
          }
          if (id == kOpenFolderButtonId) {
            wchar_t widePath[MAX_PATH * 2] = {};
            if (::MultiByteToWideChar(CP_UTF8, 0, sCrashDialogReportPath, -1, widePath, MAX_PATH * 2) != 0) {
              wchar_t* lastSlash = std::wcsrchr(widePath, L'\\');
              if (lastSlash != nullptr) {
                *(lastSlash + 1) = L'\0';
                (void)::ShellExecuteW(nullptr, L"open", widePath, nullptr, nullptr, SW_SHOWNORMAL);
              }
            }
            return TRUE;
          }
          if (id == kCloseButtonId || id == IDCANCEL) {
            (void)::EndDialog(dialog, 0);
            return TRUE;
          }
          break;
        }
        case WM_CLOSE:
          (void)::EndDialog(dialog, 0);
          return TRUE;
        default:
          break;
      }
      return FALSE;
    }

    // DLGTEMPLATE with zero children (children are created in WM_INITDIALOG).
    // Fixed static buffer, DWORD-aligned (DLGTEMPLATE requirement),
    // WORD-aligned field writes.
    const DLGTEMPLATE* BuildCrashDialogTemplate()
    {
      alignas(DWORD) static unsigned char templateBytes[512];
      unsigned char* p = templateBytes;
      auto putWord = [&p](const unsigned short value) {
        *reinterpret_cast<unsigned short*>(p) = value;
        p += 2;
      };
      auto putDword = [&p](const unsigned long value) {
        *reinterpret_cast<unsigned long*>(p) = value;
        p += 4;
      };
      auto putString = [&p](const wchar_t* const text) {
        for (const wchar_t* c = text; *c != L'\0'; ++c) {
          *reinterpret_cast<unsigned short*>(p) = static_cast<unsigned short>(*c);
          p += 2;
        }
        *reinterpret_cast<unsigned short*>(p) = 0;
        p += 2;
      };

      // DLGTEMPLATE
      putDword(WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_CENTER | DS_MODALFRAME | WS_SIZEBOX | WS_MINIMIZEBOX);
      putDword(0);   // dwExtendedStyle
      putWord(0);    // cdit (children created manually)
      putWord(10);   // x
      putWord(10);   // y
      putWord(500);  // cx, dialog units
      putWord(350);  // cy, dialog units
      putString(L""); // menu: none
      putString(L""); // class: default dialog
      putString(L"FAF crash report");

      return reinterpret_cast<const DLGTEMPLATE*>(templateBytes);
    }

  } // namespace

  void ShowCrashReportDialog(const char* const reportPath)
  {
    // Unattended runs (test scripts): FAF_CRASH_NO_DIALOG=1 keeps the report
    // and minidump but lets the process end instead of waiting on the dialog.
    if (const char* const noDialog = std::getenv("FAF_CRASH_NO_DIALOG"); noDialog != nullptr && noDialog[0] == '1') {
      return;
    }
    const char* const path = (reportPath != nullptr) ? reportPath : CrashReportPath();

    // Read the report text (bounded) into a wide buffer for the edit control.
    std::FILE* const source = std::fopen(path, "rb");
    if (source == nullptr) {
      ::MessageBoxW(nullptr, L"FAF crashed. The report file could not be read.", L"FAF crash", MB_ICONERROR | MB_OK);
      return;
    }
    (void)std::fseek(source, 0, SEEK_END);
    long bytes = std::ftell(source);
    (void)std::fseek(source, 0, SEEK_SET);
    if (bytes <= 0) {
      bytes = 0;
    }
    if (bytes > 512 * 1024) {
      bytes = 512 * 1024; // the edit control caps here; the clipboard copy takes the whole file
    }
    const std::size_t textBytes = static_cast<std::size_t>(bytes);

    wchar_t* wide = nullptr;
    char* utf8 = static_cast<char*>(::HeapAlloc(::GetProcessHeap(), 0, textBytes + 1));
    if (utf8 != nullptr) {
      const std::size_t read = std::fread(utf8, 1, textBytes, source);
      utf8[read] = '\0';
      const int wideChars = ::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
      if (wideChars > 0) {
        wide = static_cast<wchar_t*>(
          ::HeapAlloc(::GetProcessHeap(), 0, static_cast<std::size_t>(wideChars) * sizeof(wchar_t))
        );
        if (wide != nullptr) {
          (void)::MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, wideChars);
        }
      }
      (void)::HeapFree(::GetProcessHeap(), 0, utf8);
    }
    (void)std::fclose(source);

    if (wide == nullptr) {
      ::MessageBoxW(
        nullptr,
        L"FAF crashed. The report file is too large or unreadable; find faf_crash_latest.txt beside the game exe.",
        L"FAF crash", MB_ICONERROR | MB_OK
      );
      return;
    }

    (void)::strcpy_s(sCrashDialogReportPath, sizeof(sCrashDialogReportPath), path);
    sCrashDialogText = wide;

    (void)::DialogBoxIndirectParamW(
      ::GetModuleHandleW(nullptr), BuildCrashDialogTemplate(), nullptr, &CrashReportDialogProc, 0
    );

    sCrashDialogText = nullptr;
    (void)::HeapFree(::GetProcessHeap(), 0, wide);
  }

  namespace
  {
    [[maybe_unused]] const bool gCrashReportDialogSet = (sCrashReportDialog = &ShowCrashReportDialog, true);
  } // namespace
} // namespace gpg::diag
