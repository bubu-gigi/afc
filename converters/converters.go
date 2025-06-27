package converters

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"afc/utils"
)

func runZTool(toolName string, inputPath string, outputPath string) error {
	exe := utils.FindToolExe(toolName)
	cmd := exec.Command(exe, "-f", inputPath, "--csv", outputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ZTool:%s] Error analyzing %s: %v\n%s\n", toolName, inputPath, err, output)
		return err
	}
	fmt.Printf("[ZTool:%s] Analyzed %s -> %s\n", toolName, inputPath, outputPath)
	return nil
}

func runZToolToDir(toolName string, inputPath string, outputDir string) error {
	exe := utils.FindToolExe(toolName)
	cmd := exec.Command(exe, "-f", inputPath, "--csv", outputDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ZTool:%s] Error analyzing %s: %v\n%s\n", toolName, inputPath, err, output)
		return err
	}
	fmt.Printf("[ZTool:%s] Analyzed %s -> %s\n", toolName, inputPath, outputDir)
	return nil
}

func ConvertPfToCsv(pf []string) {
	for _, path := range pf {
		runZTool("PECmd.exe", path, path+".csv")
	}
}

func ConvertJumpListToCsv(jumpLists []string) {
	for _, path := range jumpLists {
		runZTool("JLECmd.exe", path, path+".csv")
	}
}

func ConvertEventLogsToCsv(evtxFiles []string) {
	for _, path := range evtxFiles {
		runZTool("EvtxECmd.exe", path, path+".csv")
	}
}

func ConvertLnkFilesToCsv(lnkFiles []string) {
	for _, path := range lnkFiles {
		runZTool("LECmd.exe", path, path+".csv")
	}
}

func ConvertWindowsTimelineToCsv(timelineFiles []string) {
	for _, path := range timelineFiles {
		runZTool("WxTCmd.exe", path, path+".csv")
	}
}

func ConvertRecycleBinToCsv(recycleBin []string) {
	for _, path := range recycleBin {
		runZTool("RBCmd.exe", path, path+".csv")
	}
}

func ConvertSrumToCsv(srumFiles []string) {
	for _, path := range srumFiles {
		runZTool("SRUMECmd.exe", path, path+".csv")
	}
}

func ConvertAmcacheToCsv(amcacheFiles []string) {
	for _, path := range amcacheFiles {
		runZTool("AmcacheParser.exe", path, path+".csv")
	}
}

func ConvertMftToCsv(mftFiles []string) {
	for _, path := range mftFiles {
		runZTool("MFTECmd.exe", path, path+".csv")
	}
}

func ConvertRegistryToCsv(registryFiles []string) {
	for _, hive := range registryFiles {
		outDir := hive + "_recmd_out"
		runZToolToDir("RECmd.exe", hive, outDir)
	}
}

func ConvertScheduledTasksToCsv(taskFiles []string) {
	for _, task := range taskFiles {
		runZToolToDir("JobParser.exe", task, filepath.Dir(task))
	}
}

func ConvertThumbcacheToCsv(thumbFiles []string) {
	tcCmd := utils.FindToolExe("ThumbCacheViewer.exe")
	for _, tcPath := range thumbFiles {
		outFile := tcPath + ".csv"
		cmd := exec.Command(tcCmd, "-t", tcPath, "-c", "-o", outFile)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", tcPath, err, output)
		} else {
			fmt.Printf("ThumbCacheViewer analyzed %s -> %s\n", tcPath, outFile)
		}
	}
}

func ConvertUsnJrnlToCsv(usnFiles []string) {
	usnCmd := utils.FindToolExe("UsnJrnl2Csv.exe")
	for _, usnPath := range usnFiles {
		outFile := usnPath + ".csv"
		cmd := exec.Command(usnCmd,
			"/UsnJrnlFile:"+usnPath,
			"/OutputPath:"+outFile,
			"/ScanMode:2",
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n%s\n", usnPath, err, output)
		} else {
			fmt.Printf("UsnJrnl2Csv analyzed %s -> %s\n", usnPath, outFile)
		}
	}
}
