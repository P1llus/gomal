//go:build windows
// +build windows

package injection

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func createProcess() windows.ProcessInformation {
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	windows.CreateProcess(syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe"), syscall.StringToUTF16Ptr(""), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	return *procInfo
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
