package collect

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// Shortcut is what a .lnk file launches.
type Shortcut struct {
	Target    string
	Arguments string
}

const (
	lnkHasIDList    = 0x1
	lnkHasLinkInfo  = 0x2
	lnkHasName      = 0x4
	lnkHasRelPath   = 0x8
	lnkHasWorkDir   = 0x10
	lnkHasArguments = 0x20
	lnkIsUnicode    = 0x80
)

// ParseShortcut reads the target path and arguments of a Shell Link (.lnk) file
// per MS-SHLLINK. Shortcuts to shell items without a file-system path return an
// empty Target.
func ParseShortcut(b []byte) (Shortcut, error) {
	var s Shortcut
	le := binary.LittleEndian
	if len(b) < 0x4C || le.Uint32(b[0:]) != 0x4C {
		return s, errors.New("not a shell link")
	}
	flags := le.Uint32(b[0x14:])
	off := 0x4C
	if flags&lnkHasIDList != 0 {
		if off+2 > len(b) {
			return s, errors.New("truncated id list")
		}
		off += 2 + int(le.Uint16(b[off:]))
	}
	if flags&lnkHasLinkInfo != 0 {
		if off+0x1C > len(b) {
			return s, errors.New("truncated link info")
		}
		li := b[off:]
		size := int(le.Uint32(li[0:]))
		hdr := int(le.Uint32(li[4:]))
		liFlags := le.Uint32(li[8:])
		// The header fields read below sit inside the structure itself, so the
		// declared size must cover them: a crafted .lnk in the Startup folder
		// must not be able to crash the scanner.
		if size < 0x1C || size > len(li) || hdr > size {
			return s, errors.New("invalid link info size")
		}
		li = li[:size]
		if hdr >= 0x24 && size < 0x24 {
			return s, errors.New("invalid link info header")
		}
		if liFlags&1 != 0 { // VolumeIDAndLocalBasePath
			if hdr >= 0x24 {
				s.Target = utf16z(li, int(le.Uint32(li[0x1C:])))
			}
			if s.Target == "" {
				s.Target = ansiz(li, int(le.Uint32(li[0x10:])))
			}
			if hdr >= 0x24 && le.Uint32(li[0x20:]) != 0 {
				s.Target += utf16z(li, int(le.Uint32(li[0x20:])))
			} else {
				s.Target += ansiz(li, int(le.Uint32(li[0x18:])))
			}
		}
		off += size
	}
	// StringData follows in a fixed order; each is a count then characters.
	unicode := flags&lnkIsUnicode != 0
	for _, f := range []uint32{lnkHasName, lnkHasRelPath, lnkHasWorkDir, lnkHasArguments} {
		if flags&f == 0 {
			continue
		}
		if off+2 > len(b) {
			return s, errors.New("truncated string data")
		}
		n := int(le.Uint16(b[off:]))
		off += 2
		width := 1
		if unicode {
			width = 2
		}
		if off+n*width > len(b) {
			return s, errors.New("string data overruns file")
		}
		str := ""
		if unicode {
			u := make([]uint16, n)
			for i := range u {
				u[i] = le.Uint16(b[off+2*i:])
			}
			str = string(utf16.Decode(u))
		} else {
			str = string(b[off : off+n])
		}
		off += n * width
		if f == lnkHasArguments {
			s.Arguments = str
		}
	}
	return s, nil
}

func utf16z(b []byte, off int) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	var u []uint16
	for i := off; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// ansiz reads a NUL-terminated string in the system code page. Non-ASCII bytes
// cannot be decoded portably, so they become U+FFFD; the Unicode field is
// preferred whenever the link has one.
func ansiz(b []byte, off int) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	var r []rune
	for i := off; i < len(b) && b[i] != 0; i++ {
		if b[i] < 0x80 {
			r = append(r, rune(b[i]))
		} else {
			r = append(r, '�')
		}
	}
	return string(r)
}
