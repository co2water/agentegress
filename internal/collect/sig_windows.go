//go:build windows

package collect

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	modwintrust                              = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust                       = modwintrust.NewProc("WinVerifyTrust")
	procWTHelperProvDataFromStateData        = modwintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = modwintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain         = modwintrust.NewProc("WTHelperGetProvCertFromChain")
	procCryptCATAdminAcquireContext2         = modwintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = modwintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = modwintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = modwintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext   = modwintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATCatalogInfoFromContext       = modwintrust.NewProc("CryptCATCatalogInfoFromContext")
	modcrypt32                               = syscall.NewLazyDLL("crypt32.dll")
	procCertGetNameStringW                   = modcrypt32.NewProc("CertGetNameStringW")
)

type winGUID struct {
	Data1        uint32
	Data2, Data3 uint16
	Data4        [8]byte
}

var actionGenericVerifyV2 = winGUID{0x00AAC56B, 0xCD44, 0x11D0, [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

type wintrustFileInfo struct {
	size         uint32
	filePath     *uint16
	file         syscall.Handle
	knownSubject *winGUID
}

type wintrustCatalogInfo struct {
	size                   uint32
	catalogVersion         uint32
	catalogFilePath        *uint16
	memberTag              *uint16
	memberFilePath         *uint16
	memberFile             syscall.Handle
	calculatedFileHash     *byte
	calculatedFileHashSize uint32
	catalogContext         uintptr
	catAdmin               uintptr
}

type wintrustData struct {
	size               uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	union              unsafe.Pointer
	stateAction        uint32
	stateData          syscall.Handle
	urlReference       *uint16
	provFlags          uint32
	uiContext          uint32
	signatureSettings  uintptr
}

type catalogInfo struct {
	size        uint32
	catalogFile [260]uint16
}

const (
	wtdUINone                = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdChoiceCatalog         = 2
	wtdStateActionVerify     = 1
	wtdStateActionClose      = 2
	wtdRevocationCheckNone   = 0x10
	wtdCacheOnlyURLRetrieval = 0x1000 // never fetch CRLs/AIA: the tool must not touch the network

	trustEProviderUnknown    = 0x800B0001
	trustESubjectFormUnknown = 0x800B0003
	trustENoSignature        = 0x800B0100
	trustEBadDigest          = 0x80096010
	certEUntrustedRoot       = 0x800B0109
	trustEExplicitDistrust   = 0x800B0111
	certEChaining            = 0x800B010A
	cryptEFileError          = 0x80092003

	certNameSimpleDisplayType = 4
)

// VerifyFiles checks Authenticode signatures (embedded, then catalog) for each
// path, in parallel. Revocation is not checked, so no network access happens.
func VerifyFiles(paths []string) map[string]Signature {
	out := make(map[string]Signature, len(paths))
	var mu sync.Mutex
	work := make(chan string)
	var wg sync.WaitGroup
	for range min(runtime.NumCPU(), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				s := VerifyFile(p)
				mu.Lock()
				out[p] = s
				mu.Unlock()
			}
		}()
	}
	for _, p := range paths {
		work <- p
	}
	close(work)
	wg.Wait()
	return out
}

// VerifyFile returns the Authenticode verdict for one executable. Files on
// network locations are never opened: reading one makes Windows connect (and
// possibly authenticate) to the server, which this tool promises not to do.
func VerifyFile(path string) Signature {
	return verifyFile(path, 0)
}

func verifyFile(path string, depth int) Signature {
	if IsRemotePath(path) {
		if networkSpelling(path) {
			return Signature{Status: SigRemote, Detail: "on a network location; not opened"}
		}
		// A bare name that did not resolve, or a relative path: which file
		// runs depends on a search path or working directory we do not know.
		return Signature{Status: SigError, Detail: DetailNotFullPath}
	}
	if isReparsePoint(path) {
		// A symbolic link (WinGet puts its portable programs behind them) is
		// followed only to a local, absolute target that is not itself a link.
		target, err := os.Readlink(path)
		switch {
		case err != nil || filepath.IsAbs(target):
		case strings.HasPrefix(target, `\`) && !strings.HasPrefix(target, `\\`), strings.HasPrefix(target, `/`) && !strings.HasPrefix(target, `//`):
			// Root-relative ("\dir\x.exe"): Windows resolves it from the
			// link's volume root, not its folder (fifth review).
			target = filepath.VolumeName(path) + target
		default:
			target = filepath.Join(filepath.Dir(path), target)
		}
		if err != nil || depth > 0 || IsRemotePath(target) {
			return Signature{Status: SigError, Detail: "a link or reparse point; not followed"}
		}
		return verifyFile(target, depth+1)
	}
	p16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return Signature{Status: SigError, Detail: err.Error()}
	}
	fi := wintrustFileInfo{size: uint32(unsafe.Sizeof(wintrustFileInfo{})), filePath: p16}
	st, signer := winVerify(wtdChoiceFile, unsafe.Pointer(&fi))
	runtime.KeepAlive(p16)
	switch st {
	case 0:
		return Signature{Status: SigSigned, Signer: signer}
	case trustENoSignature, trustESubjectFormUnknown, trustEProviderUnknown:
		if s, ok := verifyCatalog(path, p16); ok {
			return s
		}
		if InstalledPackagePath(path) {
			return Signature{Status: SigPackage, Detail: "no embedded signature; covered by MSIX package signature"}
		}
		return Signature{Status: SigUnsigned}
	default:
		return verdict(st, signer, false)
	}
}

func verdict(st uint32, signer string, catalog bool) Signature {
	s := Signature{Signer: signer, Catalog: catalog}
	switch st {
	case 0:
		s.Status = SigSigned
	case trustEBadDigest:
		s.Status, s.Detail = SigInvalid, "file does not match its signature (modified after signing)"
	case certEUntrustedRoot, certEChaining:
		s.Status, s.Detail = SigInvalid, "certificate chain not trusted"
	case trustEExplicitDistrust:
		s.Status, s.Detail = SigInvalid, "certificate explicitly distrusted"
	case cryptEFileError:
		s.Status, s.Detail = SigError, "file missing or unreadable"
	default:
		s.Status, s.Detail = SigError, fmt.Sprintf("WinVerifyTrust 0x%08X", st)
	}
	return s
}

func winVerify(choice uint32, info unsafe.Pointer) (uint32, string) {
	wd := wintrustData{
		size:             uint32(unsafe.Sizeof(wintrustData{})),
		uiChoice:         wtdUINone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      choice,
		union:            info,
		stateAction:      wtdStateActionVerify,
		provFlags:        wtdRevocationCheckNone | wtdCacheOnlyURLRetrieval,
	}
	r, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	st := uint32(r)
	signer := ""
	if wd.stateData != 0 {
		signer = signerName(wd.stateData)
	}
	wd.stateAction = wtdStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&wd)))
	return st, signer
}

// cptr turns an address returned by a Win32 call into a pointer without a
// direct uintptr→unsafe.Pointer conversion.
func cptr(addr uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&addr)) }

func signerName(state syscall.Handle) string {
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	cert, _, _ := procWTHelperGetProvCertFromChain.Call(sgnr, 0)
	if cert == 0 {
		return ""
	}
	// CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... }
	pCert := *(*uintptr)(unsafe.Add(cptr(cert), 8))
	if pCert == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	n, _, _ := procCertGetNameStringW.Call(pCert, certNameSimpleDisplayType, 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n <= 1 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

// verifyCatalog handles Windows components, which are signed through system
// catalogs rather than an embedded signature.
func verifyCatalog(path string, p16 *uint16) (Signature, bool) {
	f, err := syscall.CreateFile(p16, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return Signature{}, false
	}
	defer syscall.CloseHandle(f)
	for _, alg := range []string{"SHA256", ""} {
		var algPtr *uint16
		if alg != "" {
			algPtr, _ = syscall.UTF16PtrFromString(alg)
		}
		var admin uintptr
		r, _, _ := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algPtr)), 0, 0)
		if r == 0 {
			continue
		}
		syscall.Seek(f, 0, 0)
		s, ok := catalogLookup(admin, f, p16)
		procCryptCATAdminReleaseContext.Call(admin, 0)
		if ok {
			return s, true
		}
	}
	return Signature{}, false
}

func catalogLookup(admin uintptr, f syscall.Handle, p16 *uint16) (Signature, bool) {
	var size uint32
	procCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(f), uintptr(unsafe.Pointer(&size)), 0, 0)
	if size == 0 || size > 64 {
		return Signature{}, false
	}
	hash := make([]byte, size)
	r, _, _ := procCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(f), uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&hash[0])), 0)
	if r == 0 {
		return Signature{}, false
	}
	ci, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
	if ci == 0 {
		return Signature{}, false
	}
	defer procCryptCATAdminReleaseCatalogContext.Call(admin, ci, 0)
	info := catalogInfo{size: uint32(unsafe.Sizeof(catalogInfo{}))}
	if r, _, _ := procCryptCATCatalogInfoFromContext.Call(ci, uintptr(unsafe.Pointer(&info)), 0); r == 0 {
		return Signature{}, false
	}
	tag, _ := syscall.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	wc := wintrustCatalogInfo{
		size:                   uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
		catalogFilePath:        &info.catalogFile[0],
		memberTag:              tag,
		memberFilePath:         p16,
		memberFile:             f,
		calculatedFileHash:     &hash[0],
		calculatedFileHashSize: size,
		catAdmin:               admin,
	}
	st, signer := winVerify(wtdChoiceCatalog, unsafe.Pointer(&wc))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(hash)
	return verdict(st, signer, true), true
}
