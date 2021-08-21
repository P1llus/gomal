//go:build windows
// +build windows

package injection

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func createProcess() *syscall.ProcessInformation {
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	commandLine, err := syscall.UTF16PtrFromString("C:\\Windows\\SysWOW64\\notepad.exe")

	if err != nil {
		panic(err)
	}

	err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		panic(err)
	}

	return &pi
}

// unsafe.Sizeof(windows.ProcessEntry32{})
const processEntrySize = 568

func findProcessID(name string) uint32 {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return 0
	}
	p := windows.ProcessEntry32{Size: processEntrySize}
	for {
		e := windows.Process32Next(h, &p)
		if e != nil {
			return 0
		}
		if windows.UTF16ToString(p.ExeFile[:]) == name {
			return p.ProcessID
		}
	}
}
