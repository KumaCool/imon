package appdata

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type accessPolicy struct {
	user      *windows.SID
	system    *windows.SID
	dirAttrs  windows.SecurityAttributes
	fileAttrs windows.SecurityAttributes
}

func currentAccess() (accessPolicy, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return accessPolicy{}, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return accessPolicy{}, err
	}
	sid := user.User.Sid.String()
	dir, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")")
	if err != nil {
		return accessPolicy{}, err
	}
	file, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;" + sid + ")")
	if err != nil {
		return accessPolicy{}, err
	}
	size := uint32(unsafe.Sizeof(windows.SecurityAttributes{}))
	return accessPolicy{
		user: user.User.Sid, system: system,
		dirAttrs:  windows.SecurityAttributes{Length: size, SecurityDescriptor: dir},
		fileAttrs: windows.SecurityAttributes{Length: size, SecurityDescriptor: file},
	}, nil
}

func defaultBase() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
}

func (p accessPolicy) mkdir(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(name, &p.dirAttrs)
}

func (p accessPolicy) validateParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("data directory parent is not a directory")
	}
	return nil
}

func (p accessPolicy) lock(path string) (func() error, error) {
	// Don't share delete access on the directory while SQLite is using it.
	dir, err := openHandle(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, nil)
	if err != nil {
		return nil, err
	}
	if err := p.checkPrivate(dir, true); err != nil {
		windows.CloseHandle(dir)
		return nil, err
	}
	lock, err := p.openFile(filepath.Join(path, "instance.lock"), true)
	if err != nil {
		windows.CloseHandle(dir)
		return nil, err
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(lock, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if err != nil {
		windows.CloseHandle(lock)
		windows.CloseHandle(dir)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() error {
		unlockErr := windows.UnlockFileEx(lock, 0, 1, 0, &overlapped)
		return errors.Join(unlockErr, windows.CloseHandle(lock), windows.CloseHandle(dir))
	}, nil
}

func (p accessPolicy) checkFile(path string, create bool) error {
	h, err := p.openFile(path, create)
	if !create && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

func (p accessPolicy) openFile(path string, create bool) (windows.Handle, error) {
	disposition, access := uint32(windows.OPEN_EXISTING), uint32(windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if create {
		disposition, access = windows.OPEN_ALWAYS, windows.GENERIC_READ|windows.GENERIC_WRITE
	}
	h, err := openHandle(path, access, disposition, windows.FILE_ATTRIBUTE_NORMAL, &p.fileAttrs)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if err := p.checkPrivate(h, false); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	return h, nil
}

func openHandle(path string, access, disposition, flags uint32, attrs *windows.SecurityAttributes) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, attrs,
		disposition, flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func (p accessPolicy) checkPrivate(h windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		(!directory && info.NumberOfLinks != 1) {
		return errors.New("data directory and state files must be ordinary, non-linked filesystem entries")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	privateErr := errors.New("data directory and state files must be private to the current user and Local System")
	if !owner.Equals(p.user) || dacl == nil || dacl.AceCount == 0 {
		return privateErr
	}
	if directory {
		flags, _, err := sd.Control()
		if err != nil {
			return err
		}
		if flags&windows.SE_DACL_PROTECTED == 0 {
			return privateErr
		}
	}
	userFilesInherit := false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return privateErr
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(p.user) && !sid.Equals(p.system) {
			return privateErr
		}
		if sid.Equals(p.user) && ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0 {
			userFilesInherit = true
		}
	}
	if directory && !userFilesInherit {
		return privateErr
	}
	return nil
}
