package main

import (
	"afc/converters"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	prefetch          = []string{} /* DONE */
	jumpList          = []string{}
	registry          = []string{} /* DONE */
	evtx              = []string{} /* DONE */
	pageFiles         = []string{} // https://github.com/volatilityfoundation/volatility , https://github.com/simsong/bulk_extractor
	hiberFiles        = []string{} // HiberfilConverter.exe
	powershellHistory = []string{} // easy csv as Line,Command or not(?)
	browserCache      = []string{} // TODO?
	browserHistory    = []string{} // TODO?
	scheduledTasks    = []string{}
	hostsFiles        = []string{} // as linux, is needed a csv for that?
	lnkFiles          = []string{}
	recycleBin        = []string{}
	usnJrnl           = []string{}
	windowsTimeline   = []string{}
	scheduledTaskXMLs = []string{} // how's the best wat to parse that? They are xml so we can do as we want
	werFiles          = []string{} // same for this, custom convertor?
	thumbcache        = []string{}
	bitsJobs          = []string{}
	recentLnkFiles    = []string{}
	rdpCache          = []string{}
	srumFiles         = []string{}
	wmiActivity       = []string{}
	amcache           = []string{}
	defenderLogs      = []string{} // to study, custom parser?
	eventTrace        = []string{}
	mft               = []string{}
	//memoryDumps = []string{}
)

func main() {
	printBanner()
	var rootCmd = &cobra.Command{
		Use:   "afc",
		Short: "AFC - Artifact Forensics Collector",
		Long:  `A tool for gather, analyze and elaborate windows' artifact`,
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func run() {
	collectArtifacts("./data")

	convert()

	/*converters.ConvertJumpListToCsv(jl)
	converters.ConvertLnkFilesToCsv(lnk)
	converters.ConvertWindowsTimelineToCsv(timeline)
	converters.ConvertRecycleBinToCsv(recycle)
	converters.ConvertSrumToCsv(srum)
	converters.ConvertScheduledTasksToCsv(jobs)
	converters.ConvertAmcacheToCsv(amcache)
	converters.ConvertThumbcacheToCsv(thumb)
	converters.ConvertUsnJrnlToCsv(usnjrnl)
	converters.ConvertWmiEtlToCsv(wmi)
	converters.ConvertWmiEtlToCsv(etl)*/
}

func isRegistryHive(path string) bool {
	return strings.Contains(strings.ToLower(filepath.Base(path)), "sam") ||
		strings.Contains(strings.ToLower(filepath.Base(path)), "software") ||
		strings.Contains(strings.ToLower(filepath.Base(path)), "security") ||
		strings.Contains(strings.ToLower(filepath.Base(path)), "system") ||
		strings.Contains(strings.ToLower(filepath.Base(path)), "ntuser.dat")
}

func collectArtifacts(kdest string) {

	filepath.Walk(kdest, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		lowerPath := strings.ToLower(path)

		switch {
		case strings.HasSuffix(lowerPath, ".pf"):
			prefetch = append(prefetch, path)

		case isRegistryHive(path):
			registry = append(registry, path)

		case strings.HasSuffix(lowerPath, ".evtx"):
			evtx = append(evtx, path)

		case strings.Contains(lowerPath, "pagefile.sys"):
			pageFiles = append(pageFiles, path)

		case strings.HasSuffix(lowerPath, ".automaticdestinations-ms"), strings.HasSuffix(lowerPath, ".customdestinations-ms"):
			jumpList = append(jumpList, path)

		case strings.Contains(lowerPath, "hiberfil.sys"):
			hiberFiles = append(hiberFiles, path)

		case strings.HasPrefix(filepath.Base(lowerPath), "consolehost_history.txt"):
			powershellHistory = append(powershellHistory, path)

		case filepath.Base(lowerPath) == "webcachev01.dat":
			browserCache = append(browserCache, path)

		case filepath.Base(lowerPath) == "history" || strings.HasSuffix(lowerPath, ".sqlite"):
			browserHistory = append(browserHistory, path)

		case strings.HasSuffix(lowerPath, ".job"):
			scheduledTasks = append(scheduledTasks, path)

		case filepath.Base(lowerPath) == "hosts":
			hostsFiles = append(hostsFiles, path)

		case strings.HasSuffix(lowerPath, ".lnk"):
			lnkFiles = append(lnkFiles, path)

		case strings.Contains(lowerPath, "$recycle.bin"):
			recycleBin = append(recycleBin, path)

		case strings.Contains(lowerPath, "$usnjrnl"):
			usnJrnl = append(usnJrnl, path)

		case filepath.Base(lowerPath) == "activitiescache.db":
			windowsTimeline = append(windowsTimeline, path)

		case strings.HasSuffix(lowerPath, ".xml") && strings.Contains(lowerPath, "windows\\system32\\tasks"):
			scheduledTaskXMLs = append(scheduledTaskXMLs, path)

		case strings.HasSuffix(lowerPath, ".wer"):
			werFiles = append(werFiles, path)

		case strings.HasPrefix(filepath.Base(lowerPath), "thumbcache_") && strings.HasSuffix(lowerPath, ".db"):
			thumbcache = append(thumbcache, path)

		case strings.HasPrefix(filepath.Base(lowerPath), "qmgr") && strings.HasSuffix(lowerPath, ".dat"):
			bitsJobs = append(bitsJobs, path)

		case strings.Contains(lowerPath, "\\recent\\") && strings.HasSuffix(lowerPath, ".lnk"):
			recentLnkFiles = append(recentLnkFiles, path)

		case strings.HasSuffix(lowerPath, ".bmc"):
			rdpCache = append(rdpCache, path)

		case strings.Contains(lowerPath, "\\windows\\system32\\sru\\"):
			srumFiles = append(srumFiles, path)

		case strings.Contains(lowerPath, "\\wmi-activity\\") && strings.HasSuffix(lowerPath, ".etl"):
			wmiActivity = append(wmiActivity, path)

		case strings.Contains(lowerPath, "amcache.hve"):
			amcache = append(amcache, path)

		case strings.Contains(lowerPath, "windows defender") && strings.HasSuffix(lowerPath, ".log"):
			defenderLogs = append(defenderLogs, path)

		case strings.HasSuffix(lowerPath, ".etl"):
			eventTrace = append(eventTrace, path)

		case strings.Contains(lowerPath, "mft"):
			mft = append(mft, path)

			//case strings.HasSuffix(lowerPath, ".dmp"):
			//  memoryDumps = append(memoryDumps, path)
		}

		return nil
	})
}

func convert() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertEvtxToCsv(evtx)
		fmt.Println("Evtx converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertRegistryHiveToCsv(registry)
		fmt.Println("Registry converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertMFTToCsv(mft)
		fmt.Println("MFT converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertPrefetchToCsv(prefetch)
		fmt.Println("Prefetch converted")
	}()

  wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertPSHistoryToCsv(powershellHistory)
		fmt.Println("Powershell History converted")
	}()

	wg.Wait()
}

func printBanner() {
	c := color.New(color.FgYellow, color.Bold)
	c.Println(`
╔════════════════════════════════════╗
║       AFC - Artifact Collector     ║
║           Powered by Go            ║
╚════════════════════════════════════╝`)
}

// ──────────────── Artifact Descriptions ────────────────

// Prefetch (.pf) files:
// Used by Windows to speed up application launch. Useful to determine which programs were executed and when.

// Jump List (.automaticDestinations-ms / .customDestinations-ms):
// Stores recent documents and application usage. Helps understand user activity and file access.

// Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT):
// Core configuration and state of Windows and user accounts. Crucial for understanding installed software, users, and settings.

// Event Logs (.evtx):
// Contains logs of system, application, and security events. Useful for timeline building and incident detection.

// Pagefile.sys:
// Windows swap file. May contain remnants of memory, passwords, or file fragments.

// Hiberfil.sys:
// Stores RAM contents when system hibernates. Valuable source of volatile data snapshot.

// Memory dumps (.dmp):
// Crash or manual memory dumps. Can contain sensitive data and running process context.

// PowerShell history (consolehost_history.txt):
// Command history of PowerShell sessions. Indicates administrator or attacker commands.

// Browser cache (webcachev01.dat):
// Temporary storage of visited websites and media. Useful for reconstructing browsing activity.

// Browser history (history / .sqlite):
// URLs, timestamps, and navigation info from browsers like Chrome or Firefox.

// Scheduled tasks (.job, tasks XML):
// Lists tasks scheduled to run automatically. Good for detecting persistence mechanisms or automation.

// Hosts file:
// Maps hostnames to IPs. May show signs of tampering or blocking of services (e.g., AV or updates).

// LNK files (.lnk):
// Windows shortcuts. Reveal accessed files, locations, and timestamps.

// Recycle Bin ($Recycle.Bin):
// Deleted files metadata. Helps recover file deletion events and content.

// USN Journal ($UsnJrnl):
// Records changes to NTFS volumes. Great for file timeline and identifying tampering.

// Windows Timeline (ActivitiesCache.db):
// Tracks user activity across apps and devices. Useful for understanding session behavior.

// Scheduled task XMLs:
// XML definitions of scheduled jobs. Offers detailed insight into task parameters and triggers.

// WER files (.wer):
// Windows Error Reporting files. Contains crash data and environment context.

// Thumbcache_*.db:
// Stores thumbnail images of files and folders. Shows visual evidence of viewed files, even if deleted.

// BITS Jobs (qmgr*.dat):
// Background Intelligent Transfer Service queue. Can be abused for stealthy downloads/uploads.

// Recent LNK files:
// Shortcuts to recently accessed files. Provides insight into user activity and file access.

// RDP Cache (.bmc):
// Remote Desktop Protocol graphics cache. Shows screenshots of remote sessions.

// SRUM (System Resource Usage Monitor):
// Logs network, battery, and app activity. Excellent for detecting usage patterns and anomalies.

// WMI Activity (.etl):
// Logs WMI queries. Can indicate system interrogation or malicious recon via WMI.

// Amcache (amcache.hve):
// Tracks metadata about executed files. Great for identifying first-time execution and unknown binaries.

// Defender Logs (.log):
// Windows Defender logs. May contain AV scan results and detection events.

// ETL (Event Trace Logs):
// Kernel-level event logging. Useful for performance tracing and security analysis.

// MFT ($MFT):
// Master File Table of NTFS. Contains metadata of every file. Foundation for forensic timeline.
