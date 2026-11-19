//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/jpeg"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tile = 64

type monitor struct {
	X       int  `json:"x"`
	Y       int  `json:"y"`
	W       int  `json:"w"`
	H       int  `json:"h"`
	Primary bool `json:"primary"`
}

type rect struct{ left, top, right, bottom int32 }

type monitorInfo struct {
	size    uint32
	monitor rect
	work    rect
	flags   uint32
}

var (
	monList []monitor
	monCb   = syscall.NewCallback(func(h, hdc, r, lp uintptr) uintptr {
		mi := monitorInfo{size: uint32(unsafe.Sizeof(monitorInfo{}))}
		pGetMonitorInfoW.Call(h, uintptr(unsafe.Pointer(&mi)))
		m := mi.monitor
		monList = append(monList, monitor{X: int(m.left), Y: int(m.top), W: int(m.right - m.left), H: int(m.bottom - m.top), Primary: mi.flags&1 != 0})
		return 1
	})
)

// monitors lists the displays, primary first.
func monitors() []monitor {
	monList = nil
	pEnumDisplayMonitors.Call(0, 0, monCb, 0)
	out := make([]monitor, 0, len(monList))
	for _, m := range monList {
		if m.Primary {
			out = append([]monitor{m}, out...)
		} else {
			out = append(out, m)
		}
	}
	return out
}

func setDPIAware() {
	if pSetProcessDpiAwareCtx.Find() == nil {
		if r, _, _ := pSetProcessDpiAwareCtx.Call(^uintptr(3)); r != 0 { // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
			return
		}
	}
	pSetProcessDPIAware.Call()
}

type bitmapInfoHeader struct {
	size                          uint32
	width, height                 int32
	planes, bitCount              uint16
	compression, sizeImage        uint32
	xPels, yPels, clrUsed, clrImp int32
}

type capturer struct {
	quality  int
	full     bool
	deskName string
	hdesk    uintptr
	memDC    uintptr
	bmp      uintptr
	bits     []byte
	w, h     int
	prev     []byte
	out      bytes.Buffer
	rgba     *image.RGBA
}

// attach follows the input desktop (it changes for the sign-in screen, Ctrl+Alt+Del and UAC prompts). True when it
// changed.
func (c *capturer) attach() bool {
	const genericAll = 0x10000000
	h, _, _ := pOpenInputDesktop.Call(0, 0, genericAll)
	if h == 0 {
		return false
	}
	name := deskName(h)
	if name == c.deskName && c.hdesk != 0 {
		pCloseDesktop.Call(h)
		return false
	}
	if r, _, _ := pSetThreadDesktop.Call(h); r == 0 {
		pCloseDesktop.Call(h)
		return false
	}
	if c.hdesk != 0 {
		pCloseDesktop.Call(c.hdesk)
	}
	c.hdesk, c.deskName, c.full = h, name, true
	return true
}

func deskName(h uintptr) string {
	var buf [128]uint16
	var n uint32
	pGetUserObjectInfoW.Call(h, 2, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&n))) // UOI_NAME
	return windows.UTF16ToString(buf[:])
}

func (c *capturer) free() {
	if c.bmp != 0 {
		pDeleteObject.Call(c.bmp)
		c.bmp = 0
	}
	if c.memDC != 0 {
		pDeleteDC.Call(c.memDC)
		c.memDC = 0
	}
}

func (c *capturer) ensure(w, h int) bool {
	if c.memDC != 0 && c.w == w && c.h == h {
		return true
	}
	c.free()
	screen, _, _ := pGetDC.Call(0)
	defer pReleaseDC.Call(0, screen)
	c.memDC, _, _ = pCreateCompatibleDC.Call(screen)
	bi := bitmapInfoHeader{size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), width: int32(w), height: -int32(h), planes: 1, bitCount: 32}
	var bits unsafe.Pointer
	c.bmp, _, _ = pCreateDIBSection.Call(c.memDC, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if c.bmp == 0 || bits == nil {
		c.free()
		return false
	}
	pSelectObject.Call(c.memDC, c.bmp)
	c.bits = unsafe.Slice((*byte)(bits), w*h*4)
	c.w, c.h = w, h
	c.prev = make([]byte, w*h*4)
	c.rgba = image.NewRGBA(image.Rect(0, 0, w, h))
	c.full = true
	return true
}

type cursorInfo struct {
	size   uint32
	flags  uint32
	cursor uintptr
	x, y   int32
}

type iconInfo struct {
	fIcon              int32
	xHotspot, yHotspot uint32
	hbmMask, hbmColor  uintptr
}

// frame captures the monitor and returns the changed parts as JPEG tiles, or nil when nothing changed.
// Message: 'F', u16 width, u16 height, u16 count, then count x (u16 x, u16 y, u16 w, u16 h, u32 len, JPEG).
func (c *capturer) frame(m monitor) []byte {
	if m.W <= 0 || m.H <= 0 || !c.ensure(m.W, m.H) {
		return nil
	}
	screen, _, _ := pGetDC.Call(0)
	if screen == 0 {
		return nil
	}
	const srccopy, captureblt = 0x00CC0020, 0x40000000
	pBitBlt.Call(c.memDC, 0, 0, uintptr(m.W), uintptr(m.H), screen, uintptr(m.X), uintptr(m.Y), srccopy|captureblt)
	pReleaseDC.Call(0, screen)
	ci := cursorInfo{size: uint32(unsafe.Sizeof(cursorInfo{}))}
	if r, _, _ := pGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r != 0 && ci.flags&1 != 0 {
		var ii iconInfo
		if r, _, _ := pGetIconInfo.Call(ci.cursor, uintptr(unsafe.Pointer(&ii))); r != 0 {
			x, y := int(ci.x)-m.X-int(ii.xHotspot), int(ci.y)-m.Y-int(ii.yHotspot)
			pDrawIconEx.Call(c.memDC, uintptr(x), uintptr(y), ci.cursor, 0, 0, 0, 0, 3) // DI_NORMAL
			if ii.hbmMask != 0 {
				pDeleteObject.Call(ii.hbmMask)
			}
			if ii.hbmColor != 0 {
				pDeleteObject.Call(ii.hbmColor)
			}
		}
	}
	full := c.full
	c.full = false
	stride := c.w * 4
	type run struct{ x, y, w, h int }
	var runs []run
	for ty := 0; ty < c.h; ty += tile {
		th := min(tile, c.h-ty)
		start := -1
		for tx := 0; tx < c.w; tx += tile {
			tw := min(tile, c.w-tx)
			changed := full
			for y := ty; !changed && y < ty+th; y++ {
				o := y*stride + tx*4
				changed = !bytes.Equal(c.bits[o:o+tw*4], c.prev[o:o+tw*4])
			}
			if changed && start < 0 {
				start = tx
			} else if !changed && start >= 0 {
				runs = append(runs, run{start, ty, tx - start, th})
				start = -1
			}
		}
		if start >= 0 {
			runs = append(runs, run{start, ty, c.w - start, th})
		}
	}
	if len(runs) == 0 {
		return nil
	}
	copy(c.prev, c.bits)
	// BGRA -> RGBA (the JPEG encoder's fast path), only the changed rows
	for _, r := range runs {
		for y := r.y; y < r.y+r.h; y++ {
			o := y*stride + r.x*4
			src, dst := c.bits[o:o+r.w*4], c.rgba.Pix[o:o+r.w*4]
			for i := 0; i < len(src); i += 4 {
				dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
			}
		}
	}
	c.out.Reset()
	hdr := make([]byte, 7)
	hdr[0] = 'F'
	binary.LittleEndian.PutUint16(hdr[1:], uint16(c.w))
	binary.LittleEndian.PutUint16(hdr[3:], uint16(c.h))
	binary.LittleEndian.PutUint16(hdr[5:], uint16(len(runs)))
	c.out.Write(hdr)
	var jb bytes.Buffer
	th := make([]byte, 12)
	for _, r := range runs {
		jb.Reset()
		sub := c.rgba.SubImage(image.Rect(r.x, r.y, r.x+r.w, r.y+r.h))
		if jpeg.Encode(&jb, sub, &jpeg.Options{Quality: c.quality}) != nil {
			continue
		}
		binary.LittleEndian.PutUint16(th[0:], uint16(r.x))
		binary.LittleEndian.PutUint16(th[2:], uint16(r.y))
		binary.LittleEndian.PutUint16(th[4:], uint16(r.w))
		binary.LittleEndian.PutUint16(th[6:], uint16(r.h))
		binary.LittleEndian.PutUint32(th[8:], uint32(jb.Len()))
		c.out.Write(th)
		c.out.Write(jb.Bytes())
	}
	return append([]byte(nil), c.out.Bytes()...)
}
