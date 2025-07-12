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
	jumpList          = []string{} // progress..
	registry          = []string{} /* DONE */
	evtx              = []string{} /* DONE */
	powershellHistory = []string{} /* DONE */
	browserCache      = []string{} // TODO?
	scheduledTasks    = []string{}
	lnkFiles          = []string{} /* DONE */
	recycleBin        = []string{}
	usnJrnl           = []string{}
	windowsTimeline   = []string{}
	scheduledTaskXMLs = []string{} // how's the best wat to parse that? They are xml so we can do as we want
	werFiles          = []string{} // same for this, custom convertor?
	thumbcache        = []string{}
	bitsJobs          = []string{}
	rdpCache          = []string{}
	srumFiles         = []string{}
	wmiActivity       = []string{}
	amcache           = []string{}
	defenderLogs      = []string{} // to study, custom parser?
	eventTrace        = []string{}
	mft               = []string{} /* DONE */
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

	cfg, err := loadConfig("config.yaml")
	if err != nil {
		fmt.Println("Errore loading config:", err)
		os.Exit(1)
	}

	fmt.Printf("📡 Connecting to %s:%d...\n", cfg.Wazuh.ManagerIP, cfg.Wazuh.Port)

	collectArtifacts(cfg.Paths.Input)

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
	filename := strings.ToLower(filepath.Base(path))

	switch filename {
	case "sam", "software", "security", "system":
		return true
	default:
		return strings.Contains(filename, "ntuser.dat")
	}
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

		case strings.HasSuffix(lowerPath, ".automaticdestinations-ms"), strings.HasSuffix(lowerPath, ".customdestinations-ms"):
			jumpList = append(jumpList, path)

		case strings.HasPrefix(filepath.Base(lowerPath), "consolehost_history.txt"):
			powershellHistory = append(powershellHistory, path)

		case filepath.Base(lowerPath) == "webcachev01.dat":
			browserCache = append(browserCache, path)

		case strings.HasSuffix(lowerPath, ".job"):
			scheduledTasks = append(scheduledTasks, path)

		case strings.HasSuffix(lowerPath, ".lnk"):
			lnkFiles = append(lnkFiles, path)

		case strings.Contains(lowerPath, "$i"):
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertTaskJobToCsv(scheduledTasks)
		fmt.Println("Task Jobs converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertTaskXmlToCsv(scheduledTasks)
		fmt.Println("Task Xml converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertRecycleBinToCsv(recycleBin)
		fmt.Println("Recycle Bin converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertLinkToCsv(lnkFiles)
		fmt.Println("Link converted")
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
