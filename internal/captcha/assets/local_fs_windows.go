//go:build windows

package assets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type localAssetFS struct {
	root       string
	mu         sync.Mutex
	rootHandle windows.Handle
	closeErr   error
}

func openLocalAssetFS(path string) (*localAssetFS, error) {
	clean, err := safeConfigPath(path)
	if err != nil {
		return nil, err
	}
	h, err := openWindowsDirectoryTree(clean)
	if err != nil {
		return nil, err
	}
	return &localAssetFS{root: clean, rootHandle: h}, nil
}

func (f *localAssetFS) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rootHandle == windows.InvalidHandle {
		return f.closeErr
	}
	f.closeErr = windows.CloseHandle(f.rootHandle)
	f.rootHandle = windows.InvalidHandle
	return f.closeErr
}

func (f *localAssetFS) rootDirectoryHandle() (windows.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rootHandle == windows.InvalidHandle {
		return windows.InvalidHandle, os.ErrClosed
	}
	var duplicate windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(process, f.rootHandle, process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return windows.InvalidHandle, err
	}
	return duplicate, nil
}
func (f *localAssetFS) kindPath(kind Kind) string { return filepath.Join(f.root, string(kind)) }

func (f *localAssetFS) ensureKind(kind Kind) error {
	name := string(kind)
	if err := validateWindowsComponent(name); err != nil {
		return err
	}
	root, err := f.rootDirectoryHandle()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(root)
	h, err := ntCreateRelativeDisposition(root, name, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_DIRECTORY_FILE, windows.FILE_OPEN_IF)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return validateWindowsHandle(h, f.kindPath(kind), true)
}

func (f *localAssetFS) open(kind Kind, name string) (*os.File, error) {
	if err := validateWindowsComponent(name); err != nil {
		return nil, err
	}
	dir, err := f.kindHandle(kind)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(dir)
	h, err := ntCreateRelative(dir, name, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(f.kindPath(kind), name)
	if err = validateWindowsHandle(h, path, false); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	// Constant label: handle opened under confined root; avoid user path in NewFile.
	return os.NewFile(uintptr(h), "captcha-asset-file"), nil
}
func (f *localAssetFS) readFile(kind Kind, name string, limit int64) ([]byte, error) {
	r, err := f.open(kind, name)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, limit))
}

func (f *localAssetFS) readDir(kind Kind) ([]os.DirEntry, error) {
	dir, err := f.kindHandle(kind)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(dir)
	return readWindowsDirHandle(dir)
}

func (f *localAssetFS) atomicWrite(kind Kind, name string, data []byte, mode os.FileMode) (retErr error) {
	if err := validateWindowsComponent(name); err != nil {
		return err
	}
	dir, err := f.kindHandle(kind)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(dir)
	var h windows.Handle
	var tmpName string
	for i := 0; i < 100; i++ {
		var random [16]byte
		if _, err = rand.Read(random[:]); err != nil {
			return err
		}
		tmpName = ".asset-" + hex.EncodeToString(random[:])
		h, err = ntCreateRelativeDisposition(dir, tmpName, windows.GENERIC_WRITE|windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_CREATE)
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return err
	}
	renamed := false
	tmp := os.NewFile(uintptr(h), "captcha-asset-tmp")
	closed := false
	defer func() {
		if !renamed {
			retErr = errors.Join(retErr, markWindowsHandleForDeletion(h))
		}
		if !closed {
			retErr = errors.Join(retErr, tmp.Close())
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = io.Copy(tmp, bytes.NewReader(data)); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = renameWindowsHandleRelative(h, dir, name); err != nil {
		return err
	}
	renamed = true
	closeErr := tmp.Close()
	closed = true
	return closeErr
}

func (f *localAssetFS) remove(kind Kind, name string) error {
	if err := validateWindowsComponent(name); err != nil {
		return err
	}
	dir, err := f.kindHandle(kind)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(dir)
	h, err := ntCreateRelative(dir, name, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err = validateWindowsHandle(h, name, false); err != nil {
		return err
	}
	return markWindowsHandleForDeletion(h)
}

func (f *localAssetFS) kindHandle(kind Kind) (windows.Handle, error) {
	name := string(kind)
	if err := validateWindowsComponent(name); err != nil {
		return windows.InvalidHandle, err
	}
	root, err := f.rootDirectoryHandle()
	if err != nil {
		return windows.InvalidHandle, err
	}
	defer windows.CloseHandle(root)
	h, err := ntCreateRelative(root, name, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if err = validateWindowsHandle(h, f.kindPath(kind), true); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	return h, nil
}

func ntCreateRelative(root windows.Handle, name string, access, objectType uint32) (windows.Handle, error) {
	return ntCreateRelativeDisposition(root, name, access, objectType, windows.FILE_OPEN)
}

func ntCreateRelativeDisposition(root windows.Handle, name string, access, objectType, disposition uint32) (windows.Handle, error) {
	if err := validateWindowsComponent(name); err != nil {
		return windows.InvalidHandle, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, objectType|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if status, ok := err.(windows.NTStatus); ok {
		err = status.Errno()
	}
	if err != nil {
		return windows.InvalidHandle, err
	}
	return h, nil
}

type windowsFileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

func renameWindowsHandleRelative(h, root windows.Handle, name string) error {
	name16, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	nameBytes := (len(name16) - 1) * 2
	var layout windowsFileRenameInformation
	buf := make([]byte, int(unsafe.Offsetof(layout.FileName))+nameBytes)
	info := (*windowsFileRenameInformation)(unsafe.Pointer(&buf[0]))
	info.ReplaceIfExists = windows.FILE_RENAME_REPLACE_IF_EXISTS
	info.RootDirectory = root
	info.FileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&info.FileName[0], len(name16)-1), name16[:len(name16)-1])
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtSetInformationFile(h, &iosb, &buf[0], uint32(len(buf)), windows.FileRenameInformation)
	if st, ok := err.(windows.NTStatus); ok {
		return st.Errno()
	}
	return err
}
func markWindowsHandleForDeletion(h windows.Handle) error {
	var d struct{ DeleteFile byte }
	d.DeleteFile = 1
	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d)))
}

type windowsFileIDBothDirInfo struct {
	NextEntryOffset uint32
	FileIndex       uint32
	CreationTime    int64
	LastAccessTime  int64
	LastWriteTime   int64
	ChangeTime      int64
	EndOfFile       int64
	AllocationSize  int64
	FileAttributes  uint32
	FileNameLength  uint32
	EaSize          uint32
	ShortNameLength byte
	_               byte
	ShortName       [12]uint16
	_               uint16
	FileID          int64
	FileName        [1]uint16
}
type windowsDirEntry struct {
	name  string
	attrs uint32
}

func (e windowsDirEntry) Name() string { return e.name }
func (e windowsDirEntry) IsDir() bool  { return e.attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 }
func (e windowsDirEntry) Type() os.FileMode {
	if e.IsDir() {
		return os.ModeDir
	}
	return 0
}
func (e windowsDirEntry) Info() (os.FileInfo, error) {
	return nil, errors.New("directory entry metadata is unavailable")
}
func readWindowsDirHandle(dir windows.Handle) ([]os.DirEntry, error) {
	buf := make([]byte, 64<<10)
	class := uint32(windows.FileIdBothDirectoryRestartInfo)
	var out []os.DirEntry
	for {
		err := windows.GetFileInformationByHandleEx(dir, class, &buf[0], uint32(len(buf)))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("GetFileInformationByHandleEx class %d: %w", class, err)
		}
		class = windows.FileIdBothDirectoryInfo
		for off := uint32(0); ; {
			if int(off)+int(unsafe.Offsetof(windowsFileIDBothDirInfo{}.FileName)) > len(buf) {
				return nil, errors.New("invalid Windows directory enumeration record")
			}
			x := (*windowsFileIDBothDirInfo)(unsafe.Pointer(&buf[off]))
			n := int(x.FileNameLength)
			base := int(off) + int(unsafe.Offsetof(x.FileName))
			if n%2 != 0 || base+n > len(buf) {
				return nil, errors.New("invalid Windows directory entry name")
			}
			name := windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[base])), n/2))
			if name != "." && name != ".." {
				out = append(out, windowsDirEntry{name: name, attrs: x.FileAttributes})
			}
			if x.NextEntryOffset == 0 {
				break
			}
			if x.NextEntryOffset < uint32(unsafe.Offsetof(x.FileName)) || off+x.NextEntryOffset <= off {
				return nil, errors.New("invalid Windows directory enumeration offset")
			}
			off += x.NextEntryOffset
		}
	}
}

func validateWindowsComponent(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\\/:") || strings.ContainsRune(name, 0) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return fmt.Errorf("invalid Windows captcha asset path component %q", name)
	}
	return nil
}
func openWindowsDirectoryTree(path string) (windows.Handle, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	abs = filepath.Clean(abs)
	volume := filepath.VolumeName(abs)
	if volume == "" {
		return windows.InvalidHandle, fmt.Errorf("Windows captcha asset root has no volume: %q", path)
	}
	rootPath := volume + string(filepath.Separator)
	root, err := openWindowsObject(rootPath, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.OPEN_EXISTING, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if err = validateWindowsHandle(root, rootPath, true); err != nil {
		windows.CloseHandle(root)
		return windows.InvalidHandle, err
	}
	current := root
	currentPath := rootPath
	rest := strings.TrimPrefix(abs, rootPath)
	for _, component := range strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' }) {
		if err = validateWindowsComponent(component); err != nil {
			windows.CloseHandle(current)
			return windows.InvalidHandle, err
		}
		next, openErr := ntCreateRelativeDisposition(current, component, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_DIRECTORY_FILE, windows.FILE_OPEN_IF)
		if openErr != nil {
			windows.CloseHandle(current)
			return windows.InvalidHandle, openErr
		}
		currentPath = filepath.Join(currentPath, component)
		if err = validateWindowsHandle(next, currentPath, true); err != nil {
			windows.CloseHandle(next)
			windows.CloseHandle(current)
			return windows.InvalidHandle, err
		}
		windows.CloseHandle(current)
		current = next
	}
	return current, nil
}
func openWindowsObject(path string, access, creation, extraFlags uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, creation, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS|extraFlags, 0)
}

func validateWindowsHandle(h windows.Handle, path string, wantDir bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing reparse-point captcha asset path %q", path)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDir != wantDir {
		return fmt.Errorf("captcha asset path %q has unexpected type", path)
	}
	return nil
}
