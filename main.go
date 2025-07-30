package main

import (
	"afc/config"
	"afc/converters"
	"afc/flags"
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
	prefetch          = []string{}
	jumpList          = []string{} 
	registry          = []string{} 
	evtx              = []string{} 
	powershellHistory = []string{} 
	scheduledTasks    = []string{}
	lnkFiles          = []string{} 
	recycleBin        = []string{}
	usnJrnl           = []string{}
	scheduledTaskXMLs = []string{} 
	mft               = []string{} 
)

var (
	enableLogging     bool
	dumpRequestBodies bool
	skipWazuhSend     bool	
	artifactFilter    []string
)

func main() {
	printBanner()
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	var rootCmd = &cobra.Command{
		Use:   "afc",
		Short: "AFC - Artifact Forensics Collector",
		Long:  `A tool for gather, analyze and elaborate Windows artifacts`,
		Run: func(cmd *cobra.Command, args []string) {
			if enableLogging {
				logFile, err := os.OpenFile("afc.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Printf("Error opening log file: %v\n", err)
					os.Exit(1)
				}
				log.SetOutput(logFile)
			} else {
				log.SetOutput(os.Stdout)
			}
			run()
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&flags.EnableLogging, "log", "l", false, "Enable logging on file afc.log")
	rootCmd.PersistentFlags().BoolVarP(&flags.DumpRequestBodies, "body", "b", false, "Save the requests' body into the /body folder")
	rootCmd.PersistentFlags().BoolVarP(&flags.SkipWazuhSend, "no-wazuh", "", false, "Do not send anything to Wazuh")
	rootCmd.PersistentFlags().StringSliceVarP(&flags.ArtifactFilter, "artifacts", "a", []string{"all"}, "Filter the artifacts to work with")

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

		case strings.Contains(lowerPath, "application.evtx") && !strings.Contains(lowerPath, "slack"):
			evtx = append(evtx, path)

		case strings.HasSuffix(lowerPath, ".automaticdestinations-ms"), strings.HasSuffix(lowerPath, ".customdestinations-ms"):
			jumpList = append(jumpList, path)

		case strings.HasPrefix(filepath.Base(lowerPath), "consolehost_history.txt"):
			powershellHistory = append(powershellHistory, path)

		case strings.HasSuffix(lowerPath, ".job"):
			scheduledTasks = append(scheduledTasks, path)

		case strings.HasSuffix(lowerPath, ".lnk"):
			lnkFiles = append(lnkFiles, path)

		case strings.Contains(lowerPath, "$i"):
			recycleBin = append(recycleBin, path)

		case strings.Contains(lowerPath, "$usnjrnl"):
			usnJrnl = append(usnJrnl, path)

		case strings.HasSuffix(lowerPath, ".xml") && strings.Contains(lowerPath, "windows\\system32\\tasks"):
			scheduledTaskXMLs = append(scheduledTaskXMLs, path)

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
		converters.ConvertTaskJobToCsv(scheduledTasks, cfg)
		fmt.Println("Task Jobs converted")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertTaskXmlToCsv(scheduledTaskXMLs, cfg)
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


  	wg.Add(1)
	go func() {
		defer wg.Done()
		converters.ConvertPSHistoryToCsv(powershellHistory, cfg)
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
