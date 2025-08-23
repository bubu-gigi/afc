package main

import (
	"afc/config"
	"afc/converters"
	"afc/flags"
	utils "afc/lib"
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

func main() {
	printBanner()
	printAvailableArtifacts()
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	var rootCmd = &cobra.Command{
		Use:   "afc",
		Short: "AFC - Artifact Forensics Collector",
		Long:  `A tool for gather, analyze and elaborate Windows artifacts`,
		Run: func(cmd *cobra.Command, args []string) {
			if flags.EnableLogging {
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
	rootCmd.PersistentFlags().BoolVarP(&flags.SkipWazuhSend, "no-wazuh", "nw", false, "Do not send anything to Wazuh")
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

	if !flags.SkipWazuhSend {
		fmt.Printf("Connecting to %s:%d...\n", cfg.Wazuh.ManagerIP, cfg.Wazuh.Port)
	}

	collectArtifacts(cfg.Paths.Input)

	opts := flags.GlobalOptions{
		DumpRequestBodies: flags.DumpRequestBodies,
		SkipWazuhSend:     flags.SkipWazuhSend,
	}
	convert(cfg, &opts)
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

		case utils.IsRegistryHive(path):
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

func convert(cfg *config.Config, opts *flags.GlobalOptions) {
	var wg sync.WaitGroup

	if utils.ShouldProcessArtifact("evtx") && len(evtx) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertEvtxToCsv(evtx, cfg, opts)
			fmt.Println("Evtx converted")
		}()
	}

	if utils.ShouldProcessArtifact("hive") && len(registry) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertRegistryHiveToCsv(registry, cfg, opts)
			fmt.Println("Registry converted")
		}()
	}

	if utils.ShouldProcessArtifact("mft") && len(mft) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertMFTToCsv(mft, cfg, opts)
			fmt.Println("MFT converted")
		}()
	}

	if utils.ShouldProcessArtifact("pf") && len(prefetch) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertPrefetchToCsv(prefetch, cfg, opts)
			fmt.Println("Prefetch converted")
		}()
	}

	if utils.ShouldProcessArtifact("job") && len(scheduledTasks) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertTaskJobToCsv(scheduledTasks, cfg, opts)
			fmt.Println("Task Jobs converted")
		}()
	}

	if utils.ShouldProcessArtifact("taskxml") && len(scheduledTaskXMLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertTaskXmlToCsv(scheduledTaskXMLs, cfg, opts)
			fmt.Println("Task Xml converted")
		}()
	}

	if utils.ShouldProcessArtifact("rbin") && len(recycleBin) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertRecycleBinToCsv(recycleBin, cfg, opts)
			fmt.Println("Recycle Bin converted")
		}()
	}

	if utils.ShouldProcessArtifact("lnk") && len(lnkFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertLinkToCsv(lnkFiles, cfg, opts)
			fmt.Println("Link converted")
		}()
	}

	if utils.ShouldProcessArtifact("jl") && len(jumpList) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertJumpToCsv(jumpList, cfg, opts)
			fmt.Println("Jump List converted")
		}()
	}

	if utils.ShouldProcessArtifact("ps") && len(powershellHistory) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertPSHistoryToCsv(powershellHistory, cfg, opts)
			fmt.Println("Powershell History converted")
		}()
	}

	if utils.ShouldProcessArtifact("ps") && len(powershellHistory) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertPSHistoryToCsv(powershellHistory, cfg, opts)
			fmt.Println("Powershell History converted")
		}()
	}

	if utils.ShouldProcessArtifact("journal") && len(usnJrnl) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			converters.ConvertUsnJrnlToCsv(usnJrnl, cfg, opts)
			fmt.Println("Journal converted")
		}()
	}

	wg.Wait()

	fmt.Println("Execution completed")
}

func printBanner() {
	c := color.New(color.FgYellow, color.Bold)
	c.Println(`
╔════════════════════════════════════╗
║       AFC - Artifact Collector     ║
║           Powered by Go            ║
╚════════════════════════════════════╝`)
}

func printAvailableArtifacts() {
	fmt.Println("📦 Available artifact types for --artifacts flag:")
	for _, art := range flags.ValidArtifacts {
		fmt.Printf("  - %s\n", art)
	}
	fmt.Print("  - all (process everything)\n")
}
