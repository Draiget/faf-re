"""Post numpad '+' (increase_game_speed) key presses to every window of a process.

usage: speedkeys.py <pid> [presses] [vk]
"""
import ctypes
import ctypes.wintypes as wt
import sys
import time

u32 = ctypes.WinDLL("user32", use_last_error=True)
WM_KEYDOWN, WM_KEYUP = 0x0100, 0x0101
VK_ADD = 0x6B

pid = int(sys.argv[1])
presses = int(sys.argv[2]) if len(sys.argv) > 2 else 10
vk = int(sys.argv[3], 0) if len(sys.argv) > 3 else VK_ADD

EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
hwnds = []


def collect(hwnd, _):
    p = wt.DWORD()
    u32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
    if p.value == pid:
        hwnds.append(hwnd)
        u32.EnumChildWindows(hwnd, EnumProc(child), 0)
    return True


def child(hwnd, _):
    hwnds.append(hwnd)
    return True


u32.EnumWindows(EnumProc(collect), 0)
buf = ctypes.create_unicode_buffer(256)
for h in hwnds:
    u32.GetClassNameW(h, buf, 256)
    cls = buf.value
    u32.GetWindowTextW(h, buf, 256)
    print(hex(h or 0), cls, repr(buf.value), "visible" if u32.IsWindowVisible(h) else "")
scan = u32.MapVirtualKeyW(vk, 0)
for i in range(presses):
    for h in hwnds:
        if not u32.IsWindowVisible(h):
            continue
        u32.PostMessageW(h, WM_KEYDOWN, vk, 1 | (scan << 16))
        u32.PostMessageW(h, WM_KEYUP, vk, 1 | (scan << 16) | (1 << 30) | (1 << 31))
    time.sleep(0.15)
print("posted", presses, "presses to", sum(1 for h in hwnds if u32.IsWindowVisible(h)), "visible windows")
