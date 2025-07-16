package main

import (
	"afc/config"
	"afc/converters"
	"fmt"
	"log"
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
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	logFile, err := os.OpenFile("afc.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file log: %v", err)
	}
	log.SetOutput(logFile)

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

	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Println("Errore loading config:", err)
		os.Exit(1)
	}

	fmt.Printf("📡 Connecting to %s:%d...\n", cfg.Wazuh.ManagerIP, cfg.Wazuh.Port)

	collectArtifacts(cfg.Paths.Input)

	convert(cfg)
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

		case strings.Contains(lowerPath, "application.evtx"):
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

func convert(cfg *config.Config) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertEvtxToCsv(evtx, cfg)
		fmt.Println("Evtx converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertRegistryHiveToCsv(registry, cfg)
		fmt.Println("Registry converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertMFTToCsv(mft, cfg)
		fmt.Println("MFT converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertPrefetchToCsv(prefetch, cfg)
		fmt.Println("Prefetch converted")
	}()

  	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertPSHistoryToCsv(powershellHistory, cfg)
		fmt.Println("Powershell History converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertTaskJobToCsv(scheduledTasks, cfg)
		fmt.Println("Task Jobs converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertTaskXmlToCsv(scheduledTasks, cfg)
		fmt.Println("Task Xml converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertRecycleBinToCsv(recycleBin, cfg)
		fmt.Println("Recycle Bin converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertLinkToCsv(lnkFiles, cfg)
		fmt.Println("Link converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertJumpToCsv(jumpList, cfg)
		fmt.Println("Jump List converted")
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
