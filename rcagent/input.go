//go:build windows

package main

import "unsafe"

// INPUT for SendInput, laid out for 64-bit Windows (40 bytes).
type mouseInput struct {
	typ       uint32
	_         uint32
	dx, dy    int32
	mouseData uint32
	flags     uint32
	time      uint32
	_         uint32
	extra     uintptr
}

type kbdInput struct {
	typ   uint32
	_     uint32
	vk    uint16
	scan  uint16
	flags uint32
	time  uint32
	_     uint32
	extra uintptr
	_     [8]byte
}

const (
	mouseMove     = 0x0001
	mouseAbsolute = 0x8000
	mouseVirtDesk = 0x4000
	mouseWheel    = 0x0800
	mouseHWheel   = 0x1000
	keyExtended   = 0x0001
	keyUp         = 0x0002
	keyScancode   = 0x0008
)

// b: 0 = left, 1 = middle, 2 = right (the browser's MouseEvent.button); {down, up}
var buttonFlags = [3][2]uint32{{0x0002, 0x0004}, {0x0020, 0x0040}, {0x0008, 0x0010}}

func sm(i uintptr) int32 { r, _, _ := pGetSystemMetrics.Call(i); return int32(r) }

func sendMouse(in mouseInput) {
	in.typ = 0
	pSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
}

// mouse handles mm (move), md/mu (button down/up) and wh (wheel). x and y are pixels on the shown monitor.
func mouse(m monitor, e inMsg) {
	switch e.T {
	case "mm", "md", "mu":
		if e.X < 0 || e.Y < 0 || e.X >= m.W || e.Y >= m.H {
			return
		}
		vx, vy, vw, vh := sm(76), sm(77), sm(78), sm(79) // virtual screen
		if vw < 2 || vh < 2 {
			return
		}
		ax := (int32(m.X+e.X) - vx) * 65535 / (vw - 1)
		ay := (int32(m.Y+e.Y) - vy) * 65535 / (vh - 1)
		in := mouseInput{dx: ax, dy: ay, flags: mouseMove | mouseAbsolute | mouseVirtDesk}
		if e.T != "mm" {
			if e.B < 0 || e.B > 2 {
				return
			}
			if e.T == "md" {
				in.flags |= buttonFlags[e.B][0]
			} else {
				in.flags |= buttonFlags[e.B][1]
			}
		}
		sendMouse(in)
	case "wh":
		if e.DY != 0 {
			sendMouse(mouseInput{flags: mouseWheel, mouseData: uint32(int32(-min(max(e.DY, -1200), 1200)))})
		}
		if e.DX != 0 {
			sendMouse(mouseInput{flags: mouseHWheel, mouseData: uint32(int32(min(max(e.DX, -1200), 1200)))})
		}
	}
}

// key presses or releases a key by its physical position (KeyboardEvent.code), as a scan code, so the PC's own
// keyboard layout applies. False for an unknown code.
func key(code string, down bool) bool {
	k, ok := scanCodes[code]
	if !ok {
		return false
	}
	in := kbdInput{typ: 1, scan: k & 0xff, flags: keyScancode}
	if k&0xe000 == 0xe000 {
		in.flags |= keyExtended
	}
	if !down {
		in.flags |= keyUp
	}
	pSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	return true
}

// Set 1 scan codes; 0xE0xx = extended.
var scanCodes = map[string]uint16{
	"Escape": 0x01, "Digit1": 0x02, "Digit2": 0x03, "Digit3": 0x04, "Digit4": 0x05, "Digit5": 0x06, "Digit6": 0x07,
	"Digit7": 0x08, "Digit8": 0x09, "Digit9": 0x0A, "Digit0": 0x0B, "Minus": 0x0C, "Equal": 0x0D, "Backspace": 0x0E,
	"Tab": 0x0F, "KeyQ": 0x10, "KeyW": 0x11, "KeyE": 0x12, "KeyR": 0x13, "KeyT": 0x14, "KeyY": 0x15, "KeyU": 0x16,
	"KeyI": 0x17, "KeyO": 0x18, "KeyP": 0x19, "BracketLeft": 0x1A, "BracketRight": 0x1B, "Enter": 0x1C,
	"ControlLeft": 0x1D, "KeyA": 0x1E, "KeyS": 0x1F, "KeyD": 0x20, "KeyF": 0x21, "KeyG": 0x22, "KeyH": 0x23,
	"KeyJ": 0x24, "KeyK": 0x25, "KeyL": 0x26, "Semicolon": 0x27, "Quote": 0x28, "Backquote": 0x29, "ShiftLeft": 0x2A,
	"Backslash": 0x2B, "KeyZ": 0x2C, "KeyX": 0x2D, "KeyC": 0x2E, "KeyV": 0x2F, "KeyB": 0x30, "KeyN": 0x31,
	"KeyM": 0x32, "Comma": 0x33, "Period": 0x34, "Slash": 0x35, "ShiftRight": 0x36, "NumpadMultiply": 0x37,
	"AltLeft": 0x38, "Space": 0x39, "CapsLock": 0x3A, "F1": 0x3B, "F2": 0x3C, "F3": 0x3D, "F4": 0x3E, "F5": 0x3F,
	"F6": 0x40, "F7": 0x41, "F8": 0x42, "F9": 0x43, "F10": 0x44, "NumLock": 0x45, "ScrollLock": 0x46,
	"Numpad7": 0x47, "Numpad8": 0x48, "Numpad9": 0x49, "NumpadSubtract": 0x4A, "Numpad4": 0x4B, "Numpad5": 0x4C,
	"Numpad6": 0x4D, "NumpadAdd": 0x4E, "Numpad1": 0x4F, "Numpad2": 0x50, "Numpad3": 0x51, "Numpad0": 0x52,
	"NumpadDecimal": 0x53, "IntlBackslash": 0x56, "F11": 0x57, "F12": 0x58, "IntlRo": 0x73, "IntlYen": 0x7D,
	"NumpadEnter": 0xE01C, "ControlRight": 0xE01D, "NumpadDivide": 0xE035, "PrintScreen": 0xE037,
	"AltRight": 0xE038, "Home": 0xE047, "ArrowUp": 0xE048, "PageUp": 0xE049, "ArrowLeft": 0xE04B,
	"ArrowRight": 0xE04D, "End": 0xE04F, "ArrowDown": 0xE050, "PageDown": 0xE051, "Insert": 0xE052,
	"Delete": 0xE053, "MetaLeft": 0xE05B, "MetaRight": 0xE05C, "ContextMenu": 0xE05D,
}
