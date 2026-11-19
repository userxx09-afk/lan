//go:build windows

package main

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The bar at the top of the user's screen for the whole session: who is connected, and an End button.

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSm     uintptr
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      [2]int32
	private uint32
}

const (
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmSetFont = 0x0030
	wmCommand = 0x0111
	wmApp     = 0x8000
	wsPopup   = 0x80000000
	wsVisible = 0x10000000
	wsChild   = 0x40000000
	wsBorder  = 0x00800000
	wsExTop   = 0x00000008
	wsExTool  = 0x00000080
	wsExNoAct = 0x08000000
	endButton = 1
)

type banner struct{ hwnd uintptr }

var (
	bannerEnd  func()
	bannerProc = syscall.NewCallback(func(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
		switch msg {
		case wmCommand:
			if wp&0xffff == endButton && bannerEnd != nil {
				bannerEnd()
			}
			return 0
		case wmClose:
			return 0 // only End (or the session ending) closes it
		case wmApp:
			pDestroyWindow.Call(hwnd)
			return 0
		case wmDestroy:
			pPostQuitMessage.Call(0)
			return 0
		}
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wp, lp)
		return r
	})
)

func startBanner(tech string, onEnd func()) *banner {
	b := &banner{}
	ready := make(chan struct{})
	bannerEnd = onEnd
	go func() {
		runtime.LockOSThread() // windows belong to their thread; this one stays on the Default desktop
		cls, _ := windows.UTF16PtrFromString("NetInventoryRemoteBar")
		wc := wndClassEx{size: uint32(unsafe.Sizeof(wndClassEx{})), wndProc: bannerProc, className: cls}
		wc.cursor, _, _ = pLoadCursorW.Call(0, 32512)    // IDC_ARROW
		wc.background, _, _ = pGetSysColorBrush.Call(24) // COLOR_INFOBK
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		const w, h = 470, 38
		x := int(sm(0))/2 - w/2 // centred on the primary monitor
		title, _ := windows.UTF16PtrFromString("NetInventory remote control")
		b.hwnd, _, _ = pCreateWindowExW.Call(wsExTop|wsExTool|wsExNoAct, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)),
			wsPopup|wsVisible|wsBorder, uintptr(x), 0, w, h, 0, 0, 0, 0)
		close(ready)
		if b.hwnd == 0 {
			return
		}
		font, _, _ := pGetStockObject.Call(17) // DEFAULT_GUI_FONT
		txt, _ := windows.UTF16PtrFromString("Remote control by " + tech + " (NetInventory)")
		static, _ := windows.UTF16PtrFromString("STATIC")
		button, _ := windows.UTF16PtrFromString("BUTTON")
		end, _ := windows.UTF16PtrFromString("End session")
		lbl, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(static)), uintptr(unsafe.Pointer(txt)), wsChild|wsVisible,
			10, 11, 340, 18, b.hwnd, 0, 0, 0)
		btn, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(button)), uintptr(unsafe.Pointer(end)), wsChild|wsVisible,
			360, 6, 100, 25, b.hwnd, endButton, 0, 0)
		pSendMessageW.Call(lbl, wmSetFont, font, 1)
		pSendMessageW.Call(btn, wmSetFont, font, 1)
		var m winMsg
		for {
			r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if r == 0 || int32(r) == -1 {
				return
			}
			pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}()
	<-ready
	return b
}

func (b *banner) close() {
	if b.hwnd != 0 {
		pPostMessageW.Call(b.hwnd, wmApp, 0, 0)
	}
}
