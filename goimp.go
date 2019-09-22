// Package goimp provides an impersonate fonction for windows
package goimp

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// funcs adresses
var (
	advapi32DLL                 = syscall.NewLazyDLL("advapi32.dll")
	procLogonUserW              = advapi32DLL.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = advapi32DLL.NewProc("ImpersonateLoggedOnUser")
	procGetUserName             = advapi32DLL.NewProc("GetUserNameW")
	procRevertToSelf            = advapi32DLL.NewProc("RevertToSelf")
)

//Impersonate switch to the specified user environnement
//user must use user@domain format in domain context
//always call defer Revert() after succesfull Impersonate
func Impersonate(user, pass string) error {
	//stick current goroutine in the same thread
	runtime.LockOSThread()

	//Authentication
	token, err := logonUser(user, pass)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("Authentication, %w", err)
	}
	defer syscall.CloseHandle(token)

	//impersonation
	err = impersonateUser(token)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("Impersonation, %w", err)
	}

	return nil
}

//Revert revert impersonation
func Revert() error {
	runtime.UnlockOSThread()
	rc, _, ec := syscall.Syscall(procRevertToSelf.Addr(), 0, 0, 0, 0)
	if rc == 0 {
		return fmt.Errorf("RevertToSelf fail : %w", error(ec))
	}
	return nil
}

//UserName return current username
func UserName() (string, error) {
	wuser := make([]uint16, 256)
	var size uint32 = 255
	rc, _, ec := syscall.Syscall(procGetUserName.Addr(), 2,
		uintptr(unsafe.Pointer(&wuser[0])),
		uintptr(unsafe.Pointer(&size)), 0)
	if rc == 0 {
		return "", fmt.Errorf("GetUserName fail : %w", error(ec))
	}
	return syscall.UTF16ToString(wuser), nil
}

//logonUser call LogonUserW proc (authentication)
func logonUser(user, pass string) (syscall.Handle, error) {
	var (
		token syscall.Handle //logged-on user token
		err   error
	)

	//conv to utf16
	var wuser, wpassword []uint16
	wuser, err = syscall.UTF16FromString(user)
	if err != nil {
		return token, fmt.Errorf("invalid user : %w", err)
	}
	wpassword, err = syscall.UTF16FromString(pass)
	if err != nil {
		return token, fmt.Errorf("invalid password : %w", err)
	}

	// domain : NULL (UPN format imposed), ".\0" for local users
	var domainPtr uintptr
	local := [2]uint16{uint16('.'), 0}
	if !strings.Contains(user, "@") {
		domainPtr = uintptr(unsafe.Pointer(&local[0]))
	}

	// call LogonUser
	rc, _, ec := syscall.Syscall6(procLogonUserW.Addr(), 6,
		uintptr(unsafe.Pointer(&wuser[0])),
		domainPtr,
		uintptr(unsafe.Pointer(&wpassword[0])),
		uintptr(3), //LOGON32_LOGON_NETWORK
		uintptr(0), //LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&token)))
	if rc == 0 {
		return token, fmt.Errorf("LogonUser fail : %w", error(ec))
	}
	return token, nil
}

//impersonateUser apply impersonation
func impersonateUser(token syscall.Handle) error {
	rc, _, ec := syscall.Syscall(procImpersonateLoggedOnUser.Addr(), 1, uintptr(token), 0, 0)
	if rc == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser fail : %w", error(ec))
	}
	return nil
}
