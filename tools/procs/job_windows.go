//go:build windows

package procs

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Job is a Windows job object that kills its processes when it is closed,
// which also happens when mpemu itself exits for any reason.
type Job struct {
	handle windows.Handle
}

// NewJob creates the kill-on-close job.
func NewJob() (*Job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err = windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &Job{handle: h}, nil
}

// Assign puts a running process into the job.
func (j *Job) Assign(pid int) error {
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(p)
	return windows.AssignProcessToJobObject(j.handle, p)
}

// Close kills every process still in the job.
func (j *Job) Close() {
	if j != nil && j.handle != 0 {
		_ = windows.CloseHandle(j.handle)
		j.handle = 0
	}
}
