import ctypes, sys
from ctypes import wintypes as w
dh = ctypes.WinDLL('C:/Program Files (x86)/Windows Kits/10/Debuggers/x64/dbghelp.dll')
dh.SymInitializeW.argtypes=[w.HANDLE, w.LPCWSTR, w.BOOL]
dh.SymLoadModuleExW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,w.LPCWSTR,w.LPCWSTR,ctypes.c_ulonglong,w.DWORD,ctypes.c_void_p,w.DWORD]
dh.SymLoadModuleExW.restype=ctypes.c_ulonglong
dh.SymFromAddr.argtypes=[ctypes.c_void_p,ctypes.c_ulonglong,ctypes.POINTER(ctypes.c_ulonglong),ctypes.c_void_p]
dh.SymGetLineFromAddr64.argtypes=[ctypes.c_void_p,ctypes.c_ulonglong,ctypes.POINTER(w.DWORD),ctypes.c_void_p]
dh.SymInitializeW.argtypes=[ctypes.c_void_p,w.LPCWSTR,w.BOOL]
class SYMBOL_INFO(ctypes.Structure):
    _fields_=[('SizeOfStruct',w.ULONG),('TypeIndex',w.ULONG),('Reserved',ctypes.c_ulonglong*2),('Index',w.ULONG),('Size',w.ULONG),('ModBase',ctypes.c_ulonglong),('Flags',w.ULONG),('Value',ctypes.c_ulonglong),('Address',ctypes.c_ulonglong),('Register',w.ULONG),('Scope',w.ULONG),('Tag',w.ULONG),('NameLen',w.ULONG),('MaxNameLen',w.ULONG),('Name',ctypes.c_char*1024)]
class LINE(ctypes.Structure):
    _fields_=[('SizeOfStruct',w.DWORD),('Key',ctypes.c_void_p),('LineNumber',w.DWORD),('FileName',ctypes.c_char_p),('Address',ctypes.c_ulonglong)]
exe, pdbdir = sys.argv[1], sys.argv[2]
h = ctypes.c_void_p(ctypes.windll.kernel32.GetCurrentProcess())
dh.SymSetOptions(0x2|0x10|0x200)
dh.SymInitializeW(h, pdbdir, False)
base = dh.SymLoadModuleExW(h, None, exe, None, 0x140000000, 0, None, 0)
print('base', hex(base))
for a in sys.argv[3:]:
    addr = base + int(a, 16)
    si = SYMBOL_INFO(); si.SizeOfStruct = 88; si.MaxNameLen = 1024
    d = ctypes.c_ulonglong(0)
    ok = dh.SymFromAddr(h, addr, ctypes.byref(d), ctypes.byref(si))
    ln = LINE(); ln.SizeOfStruct = ctypes.sizeof(LINE); dd = w.DWORD(0)
    okl = dh.SymGetLineFromAddr64(h, addr, ctypes.byref(dd), ctypes.byref(ln))
    print(a, si.Name.decode(errors='replace')[:150] if ok else '?', '+%d' % d.value, (ln.FileName.decode() + ':%d' % ln.LineNumber) if okl else '')
