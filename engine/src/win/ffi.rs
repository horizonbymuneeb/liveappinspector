//! Explicit Win32/NT FFI declarations.
//!
//! LiveAppInspector deliberately does **not** depend on a third-party Win32
//! binding crate: every prototype, structure layout and constant used by the
//! forensic collection path is declared here so a reviewing examiner can audit
//! the exact ABI surface the tool exposes itself to.
#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    clippy::upper_case_acronyms
)]

use std::ffi::c_void;

pub type BOOL = i32;
pub type BYTE = u8;
pub type WORD = u16;
pub type DWORD = u32;
pub type LONG = i32;
pub type ULONG = u32;
pub type UCHAR = u8;
pub type WCHAR = u16;
pub type LSTATUS = i32;
pub type NTSTATUS = i32;
pub type HRESULT = i32;
pub type SIZE_T = usize;
pub type ULONG_PTR = usize;
pub type HANDLE = *mut c_void;
pub type HWND = isize;
pub type HINSTANCE = isize;
pub type HMODULE = isize;
pub type HKEY = isize;
pub type HLOCAL = *mut c_void;
pub type PSID = *mut c_void;
pub type PACL = *mut c_void;
pub type SC_HANDLE = *mut c_void;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub const MAX_PATH: usize = 260;

// ---------------------------------------------------------------------------
// Win32 error codes we special-case in the UI / report
// ---------------------------------------------------------------------------
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_PARTIAL_COPY: u32 = 299;
pub const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
pub const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
pub const ERROR_CANCELLED: u32 = 1223;

pub fn known_status_text(code: u32) -> Option<String> {
    let s = match code {
        0 => "The operation completed successfully",
        2 => "The system cannot find the file specified",
        5 => "Access is denied (insufficient privilege / protected process)",
        6 => "The handle is invalid",
        87 => "The parameter is incorrect",
        122 => "The data area passed to a system call is too small",
        183 => "Cannot create a file when that file already exists",
        234 => "More data is available",
        259 => "No more data is available",
        299 => "Only part of a ReadProcessMemory or WriteProcessMemory request was completed",
        1150 => "The specified program requires a newer version of Windows",
        1300 => "Not all referenced privileges are assigned to the caller",
        1314 => "A required privilege is not held by the client (SeDebugPrivilege not enabled)",
        1223 => "The operation was canceled by the user",
        0xC0000022u32 => "STATUS_ACCESS_DENIED - protected or higher-integrity process",
        0xC000010Au32 => "STATUS_PROCESS_IS_TERMINATING",
        0xC000000Du32 => "STATUS_INVALID_PARAMETER",
        _ => return None,
    };
    Some(s.to_string())
}

// ---------------------------------------------------------------------------
// Basic structures
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct POINT {
    pub x: i32,
    pub y: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl RECT {
    pub fn width(&self) -> i32 {
        self.right - self.left
    }
    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LUID {
    pub LowPart: u32,
    pub HighPart: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SID_AND_ATTRIBUTES {
    pub Sid: PSID,
    pub Attributes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

// ---------------------------------------------------------------------------
// kernel32
// ---------------------------------------------------------------------------
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_SYNCHRONIZE: u32 = 0x0010_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;

pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
pub const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
pub const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
pub const TH32CS_SNAPALL: u32 = TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE;

pub const LIST_MODULES_ALL: u32 = 0x03;
pub const LIST_MODULES_32BIT: u32 = 0x01;
pub const LIST_MODULES_64BIT: u32 = 0x02;

pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;
pub const OPEN_EXISTING: u32 = 3;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub const FILE_TYPE_PIPE: u32 = 0x0003;
pub const FILE_TYPE_DISK: u32 = 0x0001;
pub const GENERIC_READ: u32 = 0x8000_0000;

pub const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

pub const COMPUTER_NAME_NETBIOS: u32 = 1;
pub const COMPUTER_NAME_DNS_HOSTNAME: u32 = 2;
pub const COMPUTER_NAME_DNS_DOMAIN: u32 = 5;

pub const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x0000_1000;
pub const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x0000_0200;
pub const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0000_0100;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: ULONG_PTR,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; MAX_PATH],
}

impl Default for PROCESSENTRY32W {
    fn default() -> Self {
        // SAFETY: plain POD
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MODULEINFO {
    pub lpBaseOfDll: *mut c_void,
    pub SizeOfImage: u32,
    pub EntryPoint: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PROCESS_MEMORY_COUNTERS {
    pub cb: u32,
    pub PageFaultCount: u32,
    pub PeakWorkingSetSize: SIZE_T,
    pub WorkingSetSize: SIZE_T,
    pub QuotaPeakPagedPoolUsage: SIZE_T,
    pub QuotaPagedPoolUsage: SIZE_T,
    pub QuotaPeakNonPagedPoolUsage: SIZE_T,
    pub QuotaNonPagedPoolUsage: SIZE_T,
    pub PagefileUsage: SIZE_T,
    pub PeakPagefileUsage: SIZE_T,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BY_HANDLE_FILE_INFORMATION {
    pub dwFileAttributes: u32,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub dwVolumeSerialNumber: u32,
    pub nFileSizeHigh: u32,
    pub nFileSizeLow: u32,
    pub nNumberOfLinks: u32,
    pub nFileIndexHigh: u32,
    pub nFileIndexLow: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RTL_OSVERSIONINFOW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u16; 128],
}

impl Default for RTL_OSVERSIONINFOW {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetLastError() -> u32;
    pub fn SetLastError(code: u32);
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetTickCount64() -> u64;
    pub fn Sleep(ms: u32);
    pub fn GetSystemTimePreciseAsFileTime(lpft: *mut u64);
    pub fn GetSystemTimeAsFileTime(lpft: *mut FILETIME);
    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: BOOL, dwProcessId: u32) -> HANDLE;
    pub fn GetProcessId(hProcess: HANDLE) -> u32;
    pub fn GetProcessTimes(
        hProcess: HANDLE,
        lpCreationTime: *mut FILETIME,
        lpExitTime: *mut FILETIME,
        lpKernelTime: *mut FILETIME,
        lpUserTime: *mut FILETIME,
    ) -> BOOL;
    pub fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut u32) -> BOOL;
    pub fn GetProcessHandleCount(hProcess: HANDLE, pdwHandleCount: *mut u32) -> BOOL;
    pub fn QueryFullProcessImageNameW(
        hProcess: HANDLE,
        dwFlags: u32,
        lpExeName: LPWSTR,
        lpdwSize: *mut u32,
    ) -> BOOL;
    pub fn IsWow64Process2(
        hProcess: HANDLE,
        pProcessMachine: *mut u16,
        pNativeMachine: *mut u16,
    ) -> BOOL;
    pub fn IsWow64Process(hProcess: HANDLE, Wow64Process: *mut BOOL) -> BOOL;
    pub fn K32EnumProcessModulesEx(
        hProcess: HANDLE,
        lphModule: *mut HMODULE,
        cb: u32,
        lpcbNeeded: *mut u32,
        dwFilterFlag: u32,
    ) -> BOOL;
    pub fn K32GetModuleInformation(
        hProcess: HANDLE,
        hModule: HMODULE,
        lpmodinfo: *mut MODULEINFO,
        cb: u32,
    ) -> BOOL;
    pub fn K32GetModuleFileNameExW(
        hProcess: HANDLE,
        hModule: HMODULE,
        lpFilename: LPWSTR,
        nSize: u32,
    ) -> u32;
    pub fn K32GetModuleBaseNameW(
        hProcess: HANDLE,
        hModule: HMODULE,
        lpBaseName: LPWSTR,
        nSize: u32,
    ) -> u32;
    pub fn K32GetProcessMemoryInfo(
        Process: HANDLE,
        ppsmemCounters: *mut PROCESS_MEMORY_COUNTERS,
        cb: u32,
    ) -> BOOL;
    pub fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *const c_void,
        lpBuffer: *mut c_void,
        nSize: SIZE_T,
        lpNumberOfBytesRead: *mut SIZE_T,
    ) -> BOOL;
    pub fn DuplicateHandle(
        hSourceProcessHandle: HANDLE,
        hSourceHandle: HANDLE,
        hTargetProcessHandle: HANDLE,
        lpTargetHandle: *mut HANDLE,
        dwDesiredAccess: u32,
        bInheritHandle: BOOL,
        dwOptions: u32,
    ) -> BOOL;
    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;
    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    pub fn ReadFile(
        hFile: HANDLE,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
    pub fn GetFileSizeEx(hFile: HANDLE, lpFileSize: *mut i64) -> BOOL;
    pub fn GetFileType(hFile: HANDLE) -> u32;
    pub fn GetFileInformationByHandle(
        hFile: HANDLE,
        lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
    ) -> BOOL;
    pub fn QueryDosDeviceW(lpDeviceName: LPCWSTR, lpTargetPath: LPWSTR, ucchMax: u32) -> u32;
    pub fn GetLogicalDriveStringsW(nBufferLength: u32, lpBuffer: LPWSTR) -> u32;
    pub fn GetComputerNameExW(NameType: u32, lpBuffer: LPWSTR, nSize: *mut u32) -> BOOL;
    pub fn ExpandEnvironmentStringsW(lpSrc: LPCWSTR, lpDst: LPWSTR, nSize: u32) -> u32;
    pub fn GetTimeZoneInformation(lpTimeZoneInformation: *mut TIME_ZONE_INFORMATION) -> u32;
    pub fn GetModuleFileNameW(hModule: HMODULE, lpFilename: LPWSTR, nSize: u32) -> u32;
    pub fn GetModuleHandleW(lpModuleName: LPCWSTR) -> HMODULE;
    pub fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HMODULE;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: *const i8) -> *mut c_void;
    pub fn FreeLibrary(hLibModule: HMODULE) -> BOOL;
    pub fn FormatMessageW(
        dwFlags: u32,
        lpSource: *const c_void,
        dwMessageId: u32,
        dwLanguageId: u32,
        lpBuffer: LPWSTR,
        nSize: u32,
        Arguments: *const *const i8,
    ) -> u32;
    pub fn LocalFree(hMem: HLOCAL) -> HLOCAL;
    pub fn GetNativeSystemInfo(lpSystemInfo: *mut c_void);
    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
    pub fn SetPriorityClass(hProcess: HANDLE, dwPriorityClass: u32) -> BOOL;
    pub fn GetPriorityClass(hProcess: HANDLE) -> u32;
    pub fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> BOOL;
}

/// Convenience: current UTC time as raw FILETIME ticks.
pub fn now_filetime() -> u64 {
    let mut ft = 0u64;
    unsafe { GetSystemTimePreciseAsFileTime(&mut ft) };
    ft
}

// ---------------------------------------------------------------------------
// user32
// ---------------------------------------------------------------------------
pub const GWL_STYLE: i32 = -16;
pub const GWL_EXSTYLE: i32 = -20;
pub const GA_ROOT: u32 = 2;
pub const GA_ROOTOWNER: u32 = 3;
pub const GW_OWNER: u32 = 4;
pub const GW_CHILD: u32 = 5;
pub const GW_HWNDNEXT: u32 = 2;

pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_LAYERED: u32 = 0x0008_0000;
pub const WS_EX_TRANSPARENT: u32 = 0x0000_0020;
pub const WS_EX_NOACTIVATE: u32 = 0x0800_0000;

pub const WM_DESTROY: u32 = 0x0002;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_SETCURSOR: u32 = 0x0020;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_HOTKEY: u32 = 0x0312;
pub const WM_QUIT: u32 = 0x0012;
pub const VK_ESCAPE: u32 = 0x1B;
pub const VK_LBUTTON: i32 = 0x01;
pub const VK_RBUTTON: i32 = 0x02;
pub const VK_F9: u32 = 0x78;

pub const MOD_ALT: u32 = 0x0001;
pub const MOD_CONTROL: u32 = 0x0002;
pub const MOD_SHIFT: u32 = 0x0004;
pub const MOD_NOREPEAT: u32 = 0x4000;

pub const SM_XVIRTUALSCREEN: i32 = 76;
pub const SM_YVIRTUALSCREEN: i32 = 77;
pub const SM_CXVIRTUALSCREEN: i32 = 78;
pub const SM_CYVIRTUALSCREEN: i32 = 79;
pub const SM_CMONITORS: i32 = 80;

pub const IDC_CROSS: u32 = 32515;
pub const IDC_ARROW: u32 = 32512;
pub const SW_HIDE: i32 = 0;
pub const SW_SHOW: i32 = 5;
pub const HWND_TOPMOST: HWND = -1;
pub const SWP_SHOWWINDOW: u32 = 0x0040;
pub const SWP_NOACTIVATE: u32 = 0x0010;
pub const SWP_NOSIZE: u32 = 0x0001;
pub const SWP_NOMOVE: u32 = 0x0002;
pub const HWND_TOP: HWND = 0;

pub const DT_CENTER: u32 = 0x0000_0001;
pub const DT_VCENTER: u32 = 0x0000_0004;
pub const DT_SINGLELINE: u32 = 0x0000_0020;
pub const DT_NOPREFIX: u32 = 0x0000_0800;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: u32,
    pub wParam: usize,
    pub lParam: isize,
    pub time: u32,
    pub pt: POINT,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WNDCLASSW {
    pub style: u32,
    pub lpfnWndProc: Option<unsafe extern "system" fn(HWND, u32, usize, isize) -> isize>,
    pub cbClsExtra: i32,
    pub cbWndExtra: i32,
    pub hInstance: HINSTANCE,
    pub hIcon: HANDLE,
    pub hCursor: HANDLE,
    pub hbrBackground: HANDLE,
    pub lpszMenuName: LPCWSTR,
    pub lpszClassName: LPCWSTR,
}

impl Default for WNDCLASSW {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PAINTSTRUCT {
    pub hdc: HDC,
    pub fErase: BOOL,
    pub rcPaint: RECT,
    pub fRestore: BOOL,
    pub fIncUpdate: BOOL,
    pub rgbReserved: [u8; 32],
}

pub type HDC = isize;

#[link(name = "user32")]
extern "system" {
    pub fn GetCursorPos(lpPoint: *mut POINT) -> BOOL;
    pub fn SetCursorPos(x: i32, y: i32) -> BOOL;
    pub fn WindowFromPoint(Point: POINT) -> HWND;
    pub fn GetAncestor(hwnd: HWND, gaFlags: u32) -> HWND;
    pub fn GetParent(hwnd: HWND) -> HWND;
    pub fn GetWindow(hwnd: HWND, uCmd: u32) -> HWND;
    pub fn GetForegroundWindow() -> HWND;
    pub fn GetDesktopWindow() -> HWND;
    pub fn IsWindow(hwnd: HWND) -> BOOL;
    pub fn GetWindowThreadProcessId(hwnd: HWND, lpdwProcessId: *mut u32) -> u32;
    pub fn GetWindowTextW(hwnd: HWND, lpString: LPWSTR, nMaxCount: i32) -> i32;
    pub fn GetWindowTextLengthW(hwnd: HWND) -> i32;
    pub fn GetClassNameW(hwnd: HWND, lpClassName: LPWSTR, nMaxCount: i32) -> i32;
    pub fn GetWindowRect(hwnd: HWND, lpRect: *mut RECT) -> BOOL;
    pub fn GetClientRect(hwnd: HWND, lpRect: *mut RECT) -> BOOL;
    pub fn GetWindowLongPtrW(hwnd: HWND, nIndex: i32) -> isize;
    pub fn IsWindowVisible(hwnd: HWND) -> BOOL;
    pub fn GetDpiForWindow(hwnd: HWND) -> u32;
    pub fn GetSystemMetrics(nIndex: i32) -> i32;
    pub fn GetAsyncKeyState(vKey: i32) -> i16;
    pub fn SetWindowLongPtrW(hwnd: HWND, nIndex: i32, dwNewLong: isize) -> isize;
    pub fn LoadCursorW(hInstance: HINSTANCE, lpCursorName: LPCWSTR) -> HANDLE;
    pub fn SetCursor(hCursor: HANDLE) -> HANDLE;
    pub fn SetCapture(hwnd: HWND) -> HWND;
    pub fn ReleaseCapture() -> BOOL;
    pub fn GetCapture() -> HWND;
    pub fn RegisterClassW(lpWndClass: *const WNDCLASSW) -> u16;
    pub fn UnregisterClassW(lpClassName: LPCWSTR, hInstance: HINSTANCE) -> BOOL;
    pub fn CreateWindowExW(
        dwExStyle: u32,
        lpClassName: LPCWSTR,
        lpWindowName: LPCWSTR,
        dwStyle: u32,
        X: i32,
        Y: i32,
        nWidth: i32,
        nHeight: i32,
        hWndParent: HWND,
        hMenu: HANDLE,
        hInstance: HINSTANCE,
        lpParam: *mut c_void,
    ) -> HWND;
    pub fn DefWindowProcW(hwnd: HWND, msg: u32, wParam: usize, lParam: isize) -> isize;
    pub fn DestroyWindow(hwnd: HWND) -> BOOL;
    pub fn ShowWindow(hwnd: HWND, nCmdShow: i32) -> BOOL;
    pub fn UpdateWindow(hwnd: HWND) -> BOOL;
    pub fn SetForegroundWindow(hwnd: HWND) -> BOOL;
    pub fn SetWindowPos(
        hwnd: HWND,
        hWndInsertAfter: HWND,
        X: i32,
        Y: i32,
        cx: i32,
        cy: i32,
        uFlags: u32,
    ) -> BOOL;
    pub fn InvalidateRect(hwnd: HWND, lpRect: *const RECT, bErase: BOOL) -> BOOL;
    pub fn GetMessageW(lpMsg: *mut MSG, hWnd: HWND, wMsgFilterMin: u32, wMsgFilterMax: u32)
        -> BOOL;
    pub fn PeekMessageW(
        lpMsg: *mut MSG,
        hWnd: HWND,
        wMsgFilterMin: u32,
        wMsgFilterMax: u32,
        wRemoveMsg: u32,
    ) -> BOOL;
    pub fn TranslateMessage(lpMsg: *const MSG) -> BOOL;
    pub fn DispatchMessageW(lpMsg: *const MSG) -> isize;
    pub fn PostQuitMessage(nExitCode: i32);
    pub fn PostMessageW(hwnd: HWND, msg: u32, wParam: usize, lParam: isize) -> BOOL;
    pub fn RegisterHotKey(hwnd: HWND, id: i32, fsModifiers: u32, vk: u32) -> BOOL;
    pub fn UnregisterHotKey(hwnd: HWND, id: i32) -> BOOL;
    pub fn GetDC(hwnd: HWND) -> HDC;
    pub fn ReleaseDC(hwnd: HWND, hdc: HDC) -> i32;
    pub fn BeginPaint(hwnd: HWND, lpPaint: *mut PAINTSTRUCT) -> HDC;
    pub fn EndPaint(hwnd: HWND, lpPaint: *const PAINTSTRUCT) -> BOOL;
    pub fn FillRect(hdc: HDC, lprc: *const RECT, hbr: HANDLE) -> i32;
    pub fn SetLayeredWindowAttributes(hwnd: HWND, crKey: u32, bAlpha: u8, dwFlags: u32) -> BOOL;
}

// ---------------------------------------------------------------------------
// gdi32
// ---------------------------------------------------------------------------
pub const TRANSPARENT: i32 = 1;
pub const DEFAULT_CHARSET: u32 = 1;
pub const FW_SEMIBOLD: i32 = 600;
pub const FW_BOLD: i32 = 700;
pub const FONT_CLEARTYPE: u32 = 0x0000_0004;

#[link(name = "gdi32")]
extern "system" {
    pub fn CreateSolidBrush(color: u32) -> HANDLE;
    pub fn CreateFontW(
        cHeight: i32,
        cWidth: i32,
        cEscapement: i32,
        cOrientation: i32,
        cWeight: i32,
        bItalic: u32,
        bUnderline: u32,
        bStrikeOut: u32,
        iCharSet: u32,
        iOutPrecision: u32,
        iClipPrecision: u32,
        iQuality: u32,
        iPitchAndFamily: u32,
        pszFaceName: LPCWSTR,
    ) -> HANDLE;
    pub fn SelectObject(hdc: HDC, h: HANDLE) -> HANDLE;
    pub fn DeleteObject(ho: HANDLE) -> BOOL;
    pub fn SetBkMode(hdc: HDC, mode: i32) -> i32;
    pub fn SetTextColor(hdc: HDC, color: u32) -> u32;
    pub fn SetBkColor(hdc: HDC, color: u32) -> u32;
    pub fn DrawTextW(
        hdc: HDC,
        lpchText: LPCWSTR,
        cchText: i32,
        lprc: *mut RECT,
        format: u32,
    ) -> i32;
    pub fn GetStockObject(i: i32) -> HANDLE;
}

pub const NULL_BRUSH: i32 = 5;
pub const RGB_WHITE: u32 = 0x00FF_FFFF;

// ---------------------------------------------------------------------------
// dwmapi
// ---------------------------------------------------------------------------
pub const DWMWA_CLOAKED: u32 = 14;
pub const DWMWA_EXTENDED_FRAME_BOUNDS: u32 = 9;

// ---------------------------------------------------------------------------
// advapi32 - tokens, registry, services
// ---------------------------------------------------------------------------
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
pub const TOKEN_QUERY_SOURCE: u32 = 0x0010;
pub const TOKEN_DUPLICATE: u32 = 0x0002;
pub const TOKEN_IMPERSONATE: u32 = 0x0004;
pub const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
pub const TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;

pub const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
pub const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x0000_0001;
pub const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
pub const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;

pub const TOKEN_USER_CLASS: u32 = 1;
pub const TOKEN_GROUPS_CLASS: u32 = 2;
pub const TOKEN_PRIVILEGES_CLASS: u32 = 3;
pub const TOKEN_OWNER_CLASS: u32 = 4;
pub const TOKEN_STATISTICS_CLASS: u32 = 10;
pub const TOKEN_ELEVATION_TYPE_CLASS: u32 = 18;
pub const TOKEN_ELEVATION_CLASS: u32 = 20;
pub const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;
pub const TOKEN_SESSION_ID_CLASS: u32 = 12;
pub const TOKEN_VIRTUALIZATION_ENABLED_CLASS: u32 = 24;
pub const TOKEN_IS_APP_CONTAINER_CLASS: u32 = 29;

pub const SECURITY_MAX_SID_SIZE: usize = 68;

pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
pub const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
pub const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
pub const SE_GROUP_RESOURCE: u32 = 0x2000_0000;

pub const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002u32 as usize as isize;
pub const HKEY_CURRENT_USER: HKEY = 0x8000_0001u32 as usize as isize;
pub const HKEY_CLASSES_ROOT: HKEY = 0x8000_0000u32 as usize as isize;
pub const KEY_READ: u32 = 0x0002_0019;
pub const KEY_WOW64_64KEY: u32 = 0x0100;
pub const KEY_WOW64_32KEY: u32 = 0x0200;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_MULTI_SZ: u32 = 7;

pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
pub const SC_MANAGER_CONNECT: u32 = 0x0001;
pub const SERVICE_WIN32: u32 = 0x0000_0030;
pub const SERVICE_DRIVER: u32 = 0x0000_000B;
pub const SERVICE_STATE_ALL: u32 = 0x0000_0003;
pub const SC_ENUM_PROCESS_INFO: u32 = 0;
pub const SERVICE_CONFIG_DESCRIPTION: u32 = 1;
pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TOKEN_STATISTICS {
    pub TokenId: LUID,
    pub AuthenticationId: LUID,
    pub ExpirationTime: i64,
    pub TokenType: u32,
    pub ImpersonationLevel: u32,
    pub DynamicCharged: u32,
    pub DynamicAvailable: u32,
    pub GroupCount: u32,
    pub PrivilegeCount: u32,
    pub ModifiedId: LUID,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SERVICE_STATUS_PROCESS {
    pub dwServiceType: u32,
    pub dwCurrentState: u32,
    pub dwControlsAccepted: u32,
    pub dwWin32ExitCode: u32,
    pub dwServiceSpecificExitCode: u32,
    pub dwCheckPoint: u32,
    pub dwWaitHint: u32,
    pub dwProcessId: u32,
    pub dwServiceFlags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SYSTEMTIME {
    pub wYear: u16,
    pub wMonth: u16,
    pub wDayOfWeek: u16,
    pub wDay: u16,
    pub wHour: u16,
    pub wMinute: u16,
    pub wSecond: u16,
    pub wMilliseconds: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TIME_ZONE_INFORMATION {
    pub Bias: i32,
    pub StandardName: [u16; 32],
    pub StandardDate: SYSTEMTIME,
    pub StandardBias: i32,
    pub DaylightName: [u16; 32],
    pub DaylightDate: SYSTEMTIME,
    pub DaylightBias: i32,
}

impl Default for TIME_ZONE_INFORMATION {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ENUM_SERVICE_STATUS_PROCESSW {
    pub lpServiceName: *const u16,
    pub lpDisplayName: *const u16,
    pub ServiceStatusProcess: SERVICE_STATUS_PROCESS,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QUERY_SERVICE_CONFIGW {
    pub dwServiceType: u32,
    pub dwStartType: u32,
    pub dwErrorControl: u32,
    pub lpBinaryPathName: *const u16,
    pub lpLoadOrderGroup: *const u16,
    pub dwTagId: u32,
    pub lpDependencies: *const u16,
    pub lpServiceStartName: *const u16,
    pub lpDisplayName: *const u16,
}

#[link(name = "advapi32")]
extern "system" {
    pub fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: u32,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;
    pub fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: u32,
        TokenInformation: *mut c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> BOOL;
    pub fn LookupAccountSidW(
        lpSystemName: LPCWSTR,
        lpSid: PSID,
        lpName: LPWSTR,
        cchName: *mut u32,
        lpReferencedDomainName: LPWSTR,
        cchReferencedDomainName: *mut u32,
        peUse: *mut u32,
    ) -> BOOL;
    pub fn LookupPrivilegeNameW(
        lpSystemName: LPCWSTR,
        lpLuid: *const LUID,
        lpName: LPWSTR,
        cchName: *mut u32,
    ) -> BOOL;
    pub fn LookupPrivilegeDisplayNameW(
        lpSystemName: LPCWSTR,
        lpName: LPCWSTR,
        lpDisplayName: LPWSTR,
        cchDisplayName: *mut u32,
        lpLanguageId: *mut u32,
    ) -> BOOL;
    pub fn LookupPrivilegeValueW(lpSystemName: LPCWSTR, lpName: LPCWSTR, lpLuid: *mut LUID)
        -> BOOL;
    pub fn AdjustTokenPrivileges(
        TokenHandle: HANDLE,
        DisableAllPrivileges: BOOL,
        NewState: *const c_void,
        BufferLength: u32,
        PreviousState: *mut c_void,
        ReturnLength: *mut u32,
    ) -> BOOL;
    pub fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut LPWSTR) -> BOOL;
    pub fn GetSidSubAuthority(Sid: PSID, nSubAuthority: u32) -> *mut u32;
    pub fn GetSidSubAuthorityCount(Sid: PSID) -> *mut u8;
    pub fn IsValidSid(Sid: PSID) -> BOOL;
    pub fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut HKEY,
    ) -> LSTATUS;
    pub fn RegQueryValueExW(
        hKey: HKEY,
        lpValueName: LPCWSTR,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> LSTATUS;
    pub fn RegEnumValueW(
        hKey: HKEY,
        dwIndex: u32,
        lpValueName: LPWSTR,
        lpcchValueName: *mut u32,
        lpReserved: *mut u32,
        lpType: *mut u32,
        lpData: *mut u8,
        lpcbData: *mut u32,
    ) -> LSTATUS;
    pub fn RegCloseKey(hKey: HKEY) -> LSTATUS;
    pub fn OpenSCManagerW(
        lpMachineName: LPCWSTR,
        lpDatabaseName: LPCWSTR,
        dwDesiredAccess: u32,
    ) -> SC_HANDLE;
    pub fn OpenServiceW(
        hSCManager: SC_HANDLE,
        lpServiceName: LPCWSTR,
        dwDesiredAccess: u32,
    ) -> SC_HANDLE;
    pub fn EnumServicesStatusExW(
        hSCManager: SC_HANDLE,
        InfoLevel: u32,
        dwServiceType: u32,
        dwServiceState: u32,
        lpServices: *mut u8,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
        lpServicesReturned: *mut u32,
        lpResumeHandle: *mut u32,
        pszGroupName: LPCWSTR,
    ) -> BOOL;
    pub fn QueryServiceConfigW(
        hService: SC_HANDLE,
        lpServiceConfig: *mut QUERY_SERVICE_CONFIGW,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
    ) -> BOOL;
    pub fn CloseServiceHandle(hSCObject: SC_HANDLE) -> BOOL;
}

// ---------------------------------------------------------------------------
// ntdll - the parts only reachable through the native API
// ---------------------------------------------------------------------------
pub const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
pub const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;
pub const PROCESS_PROTECTION_INFORMATION_CLASS: u32 = 61;

pub const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
pub const SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS: u32 = 64;
pub const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

pub const OBJECT_BASIC_INFORMATION_CLASS: u32 = 0;
pub const OBJECT_TYPE_INFORMATION_CLASS: u32 = 2;
pub const OBJECT_NAME_INFORMATION_CLASS: u32 = 1;

pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC000_0004u32 as i32;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x8000_0005u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;
pub const STATUS_ACCESS_DENIED_NT: NTSTATUS = 0xC000_0022u32 as i32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PROCESS_BASIC_INFORMATION {
    pub Reserved1: *mut c_void,
    pub PebBaseAddress: *mut c_void,
    pub Reserved2: [*mut c_void; 2],
    pub UniqueProcessId: usize,
    pub InheritedFromUniqueProcessId: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PS_PROTECTION {
    pub Level: u8,
    pub Type: u8,
    pub Audit: u8,
}

/// Truncated SYSTEM_PROCESS_INFORMATION: the layout is fixed by the x64 ABI and
/// only the fields up to `SessionId` are ever read.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub WorkingSetPrivateSize: i64,
    pub HardFaultCount: u32,
    pub NumberOfThreadsHighWatermark: u32,
    pub CycleTime: u64,
    pub CreateTime: i64,
    pub UserTime: i64,
    pub KernelTime: i64,
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: usize,
    pub InheritedFromUniqueProcessId: usize,
    pub HandleCount: u32,
    pub SessionId: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    pub Object: *mut c_void,
    pub UniqueProcessId: usize,
    pub HandleValue: usize,
    pub GrantedAccess: u32,
    pub CreatorBackTraceIndex: u16,
    pub ObjectTypeIndex: u16,
    pub HandleAttributes: u32,
    pub Reserved: u32,
}

#[link(name = "ntdll")]
extern "system" {
    pub fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
    pub fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
    pub fn NtQueryObject(
        Handle: HANDLE,
        ObjectInformationClass: u32,
        ObjectInformation: *mut c_void,
        ObjectInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;
    pub fn RtlNtStatusToDosError(Status: NTSTATUS) -> u32;
    pub fn RtlGetVersion(lpVersionInformation: *mut RTL_OSVERSIONINFOW) -> NTSTATUS;
    pub fn RtlGetCurrentPeb() -> *mut c_void;
}

// ---------------------------------------------------------------------------
// iphlpapi - connection tables
// ---------------------------------------------------------------------------
pub const AF_UNSPEC: u32 = 0;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 23;
pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
pub const UDP_TABLE_OWNER_PID: u32 = 1;
pub const NO_ERROR: u32 = 0;
pub const ERROR_INSUFFICIENT_BUFFER_IP: u32 = 122;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MIB_TCPROW_OWNER_PID {
    pub dwState: u32,
    pub dwLocalAddr: u32,
    pub dwLocalPort: u32,
    pub dwRemoteAddr: u32,
    pub dwRemotePort: u32,
    pub dwOwningPid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MIB_TCP6ROW_OWNER_PID {
    pub ucLocalAddr: [u8; 16],
    pub dwLocalScopeId: u32,
    pub dwLocalPort: u32,
    pub ucRemoteAddr: [u8; 16],
    pub dwRemoteScopeId: u32,
    pub dwRemotePort: u32,
    pub dwState: u32,
    pub dwOwningPid: u32,
}

impl Default for MIB_TCP6ROW_OWNER_PID {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MIB_UDPROW_OWNER_PID {
    pub dwLocalAddr: u32,
    pub dwLocalPort: u32,
    pub dwOwningPid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MIB_UDP6ROW_OWNER_PID {
    pub ucLocalAddr: [u8; 16],
    pub dwLocalScopeId: u32,
    pub dwLocalPort: u32,
    pub dwOwningPid: u32,
}

impl Default for MIB_UDP6ROW_OWNER_PID {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[link(name = "iphlpapi")]
extern "system" {
    pub fn GetExtendedTcpTable(
        pTcpTable: *mut c_void,
        pdwSize: *mut u32,
        bOrder: BOOL,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
    pub fn GetExtendedUdpTable(
        pUdpTable: *mut c_void,
        pdwSize: *mut u32,
        bOrder: BOOL,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

// ---------------------------------------------------------------------------
// wtsapi32 - session context
// ---------------------------------------------------------------------------
pub const WTS_CURRENT_SERVER_HANDLE: HANDLE = std::ptr::null_mut();
pub const WTSUserName: u32 = 5;
pub const WTSDomainName: u32 = 7;
pub const WTSClientProtocolType: u32 = 16;
pub const WTSClientName: u32 = 10;
pub const WTSClientAddress: u32 = 14;
pub const WTSIsRemoteSession: u32 = 29;

// ---------------------------------------------------------------------------
// shell32 - elevation relaunch and admin probing
// ---------------------------------------------------------------------------
pub const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
pub const SEE_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
pub const SW_SHOWNORMAL: i32 = 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SHELLEXECUTEINFOW {
    pub cbSize: u32,
    pub fMask: u32,
    pub hwnd: HWND,
    pub lpVerb: LPCWSTR,
    pub lpFile: LPCWSTR,
    pub lpParameters: LPCWSTR,
    pub lpDirectory: LPCWSTR,
    pub nShow: i32,
    pub hInstApp: HINSTANCE,
    pub lpIDList: *mut c_void,
    pub lpClass: LPCWSTR,
    pub hkeyClass: HKEY,
    pub dwHotKey: u32,
    pub hIcon: HANDLE,
    pub hProcess: HANDLE,
}

impl Default for SHELLEXECUTEINFOW {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[link(name = "shell32")]
extern "system" {
    pub fn ShellExecuteExW(pExecInfo: *mut SHELLEXECUTEINFOW) -> BOOL;
    #[link_name = "IsUserAnAdmin"]
    pub fn IsUserAnAdmin() -> BOOL;
}

// ---------------------------------------------------------------------------
// wintrust / crypt32 - Authenticode verification
// ---------------------------------------------------------------------------
pub const WTD_UI_NONE: u32 = 2;
pub const WTD_REVOKE_NONE: u32 = 0;
pub const WTD_REVOKE_WHOLECHAIN: u32 = 1;
pub const WTD_CHOICE_FILE: u32 = 1;
pub const WTD_CHOICE_CATALOG: u32 = 2;
pub const WTD_STATEACTION_VERIFY: u32 = 1;
pub const WTD_STATEACTION_CLOSE: u32 = 2;
pub const WTD_SAFER_FLAG: u32 = 0x0000_0100;
pub const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;
pub const WTD_DISABLE_MD2_MD4: u32 = 0x0000_2000;

pub const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    Data1: 0x00AA_C56B,
    Data2: 0xCD44,
    Data3: 0x11D0,
    Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};
pub const TRUST_E_NOSIGNATURE: HRESULT = 0x800B_0100u32 as i32;
pub const TRUST_E_SUBJECT_FORM_UNKNOWN: HRESULT = 0x800B_0003u32 as i32;
pub const TRUST_E_PROVIDER_UNKNOWN: HRESULT = 0x800B_0001u32 as i32;
pub const TRUST_E_EXPLICIT_DISTRUST: HRESULT = 0x800B_0111u32 as i32;
pub const CERT_E_UNTRUSTEDROOT: HRESULT = 0x800B_0109u32 as i32;
pub const CERT_E_EXPIRED: HRESULT = 0x800B_0101u32 as i32;
pub const CERT_E_CHAINING: HRESULT = 0x800B_010Au32 as i32;
pub const CRYPT_E_SECURITY_SETTINGS: HRESULT = 0x8009_2026u32 as i32;
pub const CERT_E_REVOKED: HRESULT = 0x800B_010Cu32 as i32;
pub const CERT_E_REVOCATION_FAILURE: HRESULT = 0x800B_010Eu32 as i32;

pub const CERT_QUERY_OBJECT_FILE: u32 = 0x0000_0001;
pub const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 1 << 10;
pub const CERT_QUERY_CONTENT_FLAG_ALL: u32 = 0x0000_1FFE;
pub const CERT_QUERY_FORMAT_FLAG_BINARY: u32 = 1 << 1;
pub const CERT_QUERY_FORMAT_FLAG_ALL: u32 = 0x0000_000E;
pub const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
pub const X509_ASN_ENCODING: u32 = 0x0000_0001;
pub const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;
pub const CERT_FIND_ANY: u32 = 0;
pub const CERT_CLOSE_STORE_CHECK_FLAG: u32 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WINTRUST_FILE_INFO {
    pub cbStruct: u32,
    pub pcwszFilePath: LPCWSTR,
    pub hFile: HANDLE,
    pub pgKnownSubject: *mut GUID,
}

impl Default for WINTRUST_FILE_INFO {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WINTRUST_CATALOG_INFO {
    pub cbStruct: u32,
    pub dwCatalogVersion: u32,
    pub pcwszCatalogFilePath: LPCWSTR,
    pub pcwszMemberTag: LPCWSTR,
    pub pcwszMemberFilePath: LPCWSTR,
    pub hMemberFile: HANDLE,
    pub pbCalculatedFileHash: *mut u8,
    pub cbCalculatedFileHash: u32,
    pub pcCatalogContext: *mut c_void,
    pub hCatAdmin: isize,
}

impl Default for WINTRUST_CATALOG_INFO {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CATALOG_INFO {
    pub cbStruct: u32,
    pub wszCatalogFile: [u16; 260],
}

impl Default for CATALOG_INFO {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WINTRUST_DATA {
    pub cbStruct: u32,
    pub pPolicyCallbackData: *mut c_void,
    pub pSIPClientData: *mut c_void,
    pub dwUIChoice: u32,
    pub fdwRevocationChecks: u32,
    pub dwUnionChoice: u32,
    /// Union member. `WINTRUST_FILE_INFO` for WTD_CHOICE_FILE and
    /// `WINTRUST_CATALOG_INFO` for WTD_CHOICE_CATALOG share this single slot, so
    /// the catalog caller casts its pointer into this field. Declaring both
    /// would shift every following field and corrupt the ABI.
    pub pFile: *mut WINTRUST_FILE_INFO,
    pub dwStateAction: u32,
    pub hWVTStateData: HANDLE,
    pub pwszURLReference: *mut u16,
    pub dwProvFlags: u32,
    pub dwUIContext: u32,
    pub pSignatureSettings: *mut c_void,
}

impl Default for WINTRUST_DATA {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CERT_CONTEXT {
    pub dwCertEncodingType: u32,
    pub pbCertEncoded: *mut u8,
    pub cbCertEncoded: u32,
    pub pCertInfo: *mut c_void,
    pub hCertStore: HANDLE,
}

#[link(name = "crypt32")]
extern "system" {
    pub fn CryptQueryObject(
        dwObjectType: u32,
        pvObject: *const c_void,
        dwExpectedContentTypeFlags: u32,
        dwExpectedFormatTypeFlags: u32,
        dwFlags: u32,
        pdwMsgAndCertEncodingType: *mut u32,
        pdwContentType: *mut u32,
        pdwFormatType: *mut u32,
        phCertStore: *mut HANDLE,
        phMsg: *mut HANDLE,
        ppvContext: *mut *mut c_void,
    ) -> BOOL;
    pub fn CertEnumCertificatesInStore(
        hCertStore: HANDLE,
        pPrevCertContext: *mut CERT_CONTEXT,
    ) -> *mut CERT_CONTEXT;
    pub fn CertGetNameStringW(
        pCertContext: *const CERT_CONTEXT,
        dwType: u32,
        dwFlags: u32,
        pvTypePara: *mut c_void,
        pszNameString: LPWSTR,
        cchNameString: u32,
    ) -> u32;
    pub fn CertFreeCertificateContext(pCertContext: *mut CERT_CONTEXT) -> BOOL;
    pub fn CertCloseStore(hCertStore: HANDLE, dwFlags: u32) -> BOOL;
    pub fn CryptMsgClose(hCryptMsg: HANDLE) -> BOOL;
}

// ---------------------------------------------------------------------------
// version.dll - file version resources
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VS_FIXEDFILEINFO {
    pub dwSignature: u32,
    pub dwStrucVersion: u32,
    pub dwFileVersionMS: u32,
    pub dwFileVersionLS: u32,
    pub dwProductVersionMS: u32,
    pub dwProductVersionLS: u32,
    pub dwFileFlagsMask: u32,
    pub dwFileFlags: u32,
    pub dwFileOS: u32,
    pub dwFileType: u32,
    pub dwFileSubtype: u32,
    pub dwFileDateMS: u32,
    pub dwFileDateLS: u32,
}

// ---------------------------------------------------------------------------
// ws2_32 - reverse DNS for endpoint attribution
// ---------------------------------------------------------------------------
pub const NI_NAMEREQD: i32 = 0x0000_0008;
pub const NI_NUMERICHOST: i32 = 0x0000_0002;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SOCKADDR_IN {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SOCKADDR_IN6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

impl Default for SOCKADDR_IN6 {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[link(name = "ws2_32")]
extern "system" {
    pub fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut c_void) -> i32;
    pub fn WSACleanup() -> i32;
    pub fn getnameinfo(
        pSockaddr: *const c_void,
        SockaddrLength: i32,
        pHost: *mut i8,
        Hostlen: u32,
        pServ: *mut i8,
        Servlen: u32,
        Flags: i32,
    ) -> i32;
}

// ---------------------------------------------------------------------------
// Runtime-resolved optional system libraries
// ---------------------------------------------------------------------------
// `dwmapi`, `wtsapi32`, `wintrust` and `version` are resolved through
// LoadLibraryW/GetProcAddress rather than the import table because:
//   * the engine keeps building on toolchains without those import libraries,
//   * Server Core / stripped SKUs may genuinely not have them, and a missing
//     optional API must degrade one report field, never the whole acquisition.

fn wz(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub struct DynLib {
    pub handle: HMODULE,
}

impl DynLib {
    pub fn load(name: &str) -> Option<Self> {
        let w = wz(name);
        let h = unsafe { LoadLibraryW(w.as_ptr()) };
        if h == 0 {
            None
        } else {
            Some(Self { handle: h })
        }
    }

    /// # Safety
    /// The caller must instantiate `T` with exactly the signature the exported
    /// symbol has; a mismatch is undefined behaviour at call time.
    pub unsafe fn sym<T: Copy>(&self, name: &str) -> Option<T> {
        let mut ansi = name.as_bytes().to_vec();
        ansi.push(0);
        let p = GetProcAddress(self.handle, ansi.as_ptr() as *const i8);
        if p.is_null() {
            None
        } else if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
            // Guard against accidentally passing a fat pointer / large struct.
            None
        } else {
            Some(std::mem::transmute_copy::<*mut c_void, T>(&p))
        }
    }
}

impl Drop for DynLib {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.handle);
        }
    }
}

// ---- dwmapi.dll ----
pub struct DwmApi {
    pub GetWindowAttribute: unsafe extern "system" fn(HWND, u32, *mut c_void, u32) -> HRESULT,
}

pub fn dwmapi() -> Option<&'static DwmApi> {
    static API: std::sync::OnceLock<Option<DwmApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let lib = DynLib::load("dwmapi.dll")?;
        let GetWindowAttribute =
            lib.sym::<unsafe extern "system" fn(HWND, u32, *mut c_void, u32) -> HRESULT>(
                "DwmGetWindowAttribute",
            )?;
        // The library is intentionally leaked so the resolved pointers stay valid
        // for the process lifetime.
        std::mem::forget(lib);
        Some(DwmApi { GetWindowAttribute })
    })
    .as_ref()
}

// ---- wtsapi32.dll ----
pub struct WtsApi {
    pub QuerySessionInformationW:
        unsafe extern "system" fn(HANDLE, u32, u32, *mut *mut u16, *mut u32) -> BOOL,
    pub FreeMemory: unsafe extern "system" fn(*mut c_void),
}

pub fn wtsapi() -> Option<&'static WtsApi> {
    static API: std::sync::OnceLock<Option<WtsApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let lib = DynLib::load("wtsapi32.dll")?;
        let QuerySessionInformationW = lib.sym::<unsafe extern "system" fn(
            HANDLE,
            u32,
            u32,
            *mut *mut u16,
            *mut u32,
        ) -> BOOL>("WTSQuerySessionInformationW")?;
        let FreeMemory = lib.sym::<unsafe extern "system" fn(*mut c_void)>("WTSFreeMemory")?;
        std::mem::forget(lib);
        Some(WtsApi {
            QuerySessionInformationW,
            FreeMemory,
        })
    })
    .as_ref()
}

// ---- wintrust.dll ----
pub struct WinTrustApi {
    pub WinVerifyTrust: unsafe extern "system" fn(HWND, *mut GUID, *mut c_void) -> HRESULT,
    pub CryptCATAdminAcquireContext2:
        unsafe extern "system" fn(*mut isize, *const GUID, LPCWSTR, *const c_void, u32) -> BOOL,
    pub CryptCATAdminCalcHashFromFileHandle2:
        unsafe extern "system" fn(isize, HANDLE, *mut u32, *mut u8, u32) -> BOOL,
    pub CryptCATAdminEnumCatalogFromHash:
        unsafe extern "system" fn(isize, *const u8, u32, u32, *mut c_void) -> *mut c_void,
    pub CryptCATCatalogInfoFromContext:
        unsafe extern "system" fn(*mut c_void, *mut CATALOG_INFO, u32) -> BOOL,
    pub CryptCATAdminReleaseCatalogContext:
        unsafe extern "system" fn(isize, *mut c_void, u32) -> BOOL,
    pub CryptCATAdminReleaseContext: unsafe extern "system" fn(isize, u32) -> BOOL,
}

pub fn wintrust() -> Option<&'static WinTrustApi> {
    static API: std::sync::OnceLock<Option<WinTrustApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let lib = DynLib::load("wintrust.dll")?;
        let WinVerifyTrust =
            lib.sym::<unsafe extern "system" fn(HWND, *mut GUID, *mut c_void) -> HRESULT>(
                "WinVerifyTrust",
            )?;
        let CryptCATAdminAcquireContext2 = lib.sym::<unsafe extern "system" fn(
            *mut isize,
            *const GUID,
            LPCWSTR,
            *const c_void,
            u32,
        ) -> BOOL>("CryptCATAdminAcquireContext2")?;
        let CryptCATAdminCalcHashFromFileHandle2 =
            lib.sym::<unsafe extern "system" fn(isize, HANDLE, *mut u32, *mut u8, u32) -> BOOL>(
                "CryptCATAdminCalcHashFromFileHandle2",
            )?;
        let CryptCATAdminEnumCatalogFromHash = lib.sym::<unsafe extern "system" fn(
            isize,
            *const u8,
            u32,
            u32,
            *mut c_void,
        )
            -> *mut c_void>(
            "CryptCATAdminEnumCatalogFromHash"
        )?;
        let CryptCATCatalogInfoFromContext =
            lib.sym::<unsafe extern "system" fn(*mut c_void, *mut CATALOG_INFO, u32) -> BOOL>(
                "CryptCATCatalogInfoFromContext",
            )?;
        let CryptCATAdminReleaseCatalogContext =
            lib.sym::<unsafe extern "system" fn(isize, *mut c_void, u32) -> BOOL>(
                "CryptCATAdminReleaseCatalogContext",
            )?;
        let CryptCATAdminReleaseContext = lib
            .sym::<unsafe extern "system" fn(isize, u32) -> BOOL>("CryptCATAdminReleaseContext")?;
        std::mem::forget(lib);
        Some(WinTrustApi {
            WinVerifyTrust,
            CryptCATAdminAcquireContext2,
            CryptCATAdminCalcHashFromFileHandle2,
            CryptCATAdminEnumCatalogFromHash,
            CryptCATCatalogInfoFromContext,
            CryptCATAdminReleaseCatalogContext,
            CryptCATAdminReleaseContext,
        })
    })
    .as_ref()
}

// ---- version.dll ----
pub struct VersionApi {
    pub GetFileVersionInfoSizeW: unsafe extern "system" fn(LPCWSTR, *mut u32) -> u32,
    pub GetFileVersionInfoW: unsafe extern "system" fn(LPCWSTR, u32, u32, *mut c_void) -> BOOL,
    pub VerQueryValueW:
        unsafe extern "system" fn(*const c_void, LPCWSTR, *mut *mut c_void, *mut u32) -> BOOL,
}

pub fn version_api() -> Option<&'static VersionApi> {
    static API: std::sync::OnceLock<Option<VersionApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let lib = DynLib::load("version.dll")?;
        let GetFileVersionInfoSizeW = lib
            .sym::<unsafe extern "system" fn(LPCWSTR, *mut u32) -> u32>(
                "GetFileVersionInfoSizeW",
            )?;
        let GetFileVersionInfoW =
            lib.sym::<unsafe extern "system" fn(LPCWSTR, u32, u32, *mut c_void) -> BOOL>(
                "GetFileVersionInfoW",
            )?;
        let VerQueryValueW = lib.sym::<unsafe extern "system" fn(
            *const c_void,
            LPCWSTR,
            *mut *mut c_void,
            *mut u32,
        ) -> BOOL>("VerQueryValueW")?;
        std::mem::forget(lib);
        Some(VersionApi {
            GetFileVersionInfoSizeW,
            GetFileVersionInfoW,
            VerQueryValueW,
        })
    })
    .as_ref()
}
