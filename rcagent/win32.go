//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	sasdll   = windows.NewLazySystemDLL("sas.dll")

	pWTSSendMessageW             = wtsapi32.NewProc("WTSSendMessageW")
	pWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	pWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")
	pSendSAS                     = sasdll.NewProc("SendSAS")

	pGetDC                 = user32.NewProc("GetDC")
	pReleaseDC             = user32.NewProc("ReleaseDC")
	pOpenInputDesktop      = user32.NewProc("OpenInputDesktop")
	pSetThreadDesktop      = user32.NewProc("SetThreadDesktop")
	pCloseDesktop          = user32.NewProc("CloseDesktop")
	pGetUserObjectInfoW    = user32.NewProc("GetUserObjectInformationW")
	pSendInput             = user32.NewProc("SendInput")
	pGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	pEnumDisplayMonitors   = user32.NewProc("EnumDisplayMonitors")
	pGetMonitorInfoW       = user32.NewProc("GetMonitorInfoW")
	pGetCursorInfo         = user32.NewProc("GetCursorInfo")
	pGetIconInfo           = user32.NewProc("GetIconInfo")
	pDrawIconEx            = user32.NewProc("DrawIconEx")
	pSetProcessDpiAwareCtx = user32.NewProc("SetProcessDpiAwarenessContext")
	pSetProcessDPIAware    = user32.NewProc("SetProcessDPIAware")
	pRegisterClassExW      = user32.NewProc("RegisterClassExW")
	pCreateWindowExW       = user32.NewProc("CreateWindowExW")
	pDefWindowProcW        = user32.NewProc("DefWindowProcW")
	pDestroyWindow         = user32.NewProc("DestroyWindow")
	pGetMessageW           = user32.NewProc("GetMessageW")
	pTranslateMessage      = user32.NewProc("TranslateMessage")
	pDispatchMessageW      = user32.NewProc("DispatchMessageW")
	pPostMessageW          = user32.NewProc("PostMessageW")
	pPostQuitMessage       = user32.NewProc("PostQuitMessage")
	pSendMessageW          = user32.NewProc("SendMessageW")
	pSetWindowPos          = user32.NewProc("SetWindowPos")
	pLoadCursorW           = user32.NewProc("LoadCursorW")
	pGetSysColorBrush      = user32.NewProc("GetSysColorBrush")

	pCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	pCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	pSelectObject       = gdi32.NewProc("SelectObject")
	pDeleteObject       = gdi32.NewProc("DeleteObject")
	pDeleteDC           = gdi32.NewProc("DeleteDC")
	pBitBlt             = gdi32.NewProc("BitBlt")
	pGetStockObject     = gdi32.NewProc("GetStockObject")
)

const (
	idYes     = 6
	idTimeout = 32000

	mbYesNo        = 0x4
	mbIconQuestion = 0x20
	mbDefButton2   = 0x100
	mbTopmost      = 0x40000
	mbSetForegrnd  = 0x10000

	wtsUserName   = 5
	wtsDomainName = 7
)

// askUser shows a Yes/No question in the user's session and waits for the answer (or the timeout).
func askUser(session uint32, title, msg string, seconds int) uint32 {
	t, _ := windows.UTF16FromString(title)
	m, _ := windows.UTF16FromString(msg)
	var resp uint32
	r, _, _ := pWTSSendMessageW.Call(0, uintptr(session), uintptr(unsafe.Pointer(&t[0])), uintptr(len(t)*2),
		uintptr(unsafe.Pointer(&m[0])), uintptr(len(m)*2), mbYesNo|mbIconQuestion|mbDefButton2|mbTopmost|mbSetForegrnd,
		uintptr(seconds), uintptr(unsafe.Pointer(&resp)), 1)
	if r == 0 {
		return 0
	}
	return resp
}

func wtsString(session uint32, class uintptr) string {
	var buf *uint16
	var n uint32
	r, _, _ := pWTSQuerySessionInformationW.Call(0, uintptr(session), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer pWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

// sessionUser is DOMAIN\user signed in to that Windows session, or "" when nobody is.
func sessionUser(session uint32) string {
	u := wtsString(session, wtsUserName)
	if u == "" {
		return ""
	}
	if d := wtsString(session, wtsDomainName); d != "" {
		return d + `\` + u
	}
	return u
}

func consoleUser() string {
	s := windows.WTSGetActiveConsoleSessionId()
	if s == 0xFFFFFFFF {
		return ""
	}
	return sessionUser(s)
}

// sendSAS is Ctrl+Alt+Del. Works from a service running as SYSTEM when SoftwareSASGeneration allows services.
func sendSAS() {
	if pSendSAS.Find() == nil {
		pSendSAS.Call(0)
	}
}
