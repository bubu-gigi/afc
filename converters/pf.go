package converters

import (
	"afc/config"
	utils "afc/lib"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	prefetch "www.velocidex.com/golang/go-prefetch"
)


func ConvertPrefetchToCsv(files []string, config *config.Config) {
	for _, file := range files {
		convertPrefetch(file, config)
	}
}

func convertPrefetch(file string, config *config.Config) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("prefetch|Error opening file %s: %v\n", file, err)
		return
	}
	defer f.Close()

	pf, err := prefetch.LoadPrefetch(f)
	if err != nil {
		fmt.Printf("prefetch|Error parsing file %s: %v\n", file, err)
		return
	}

	headers := []string{
		"Executable", "RunCount", "FileSize", "Version", "Hash", "LastRunTimes", "FilesAccessed",
		"PrefetchFilename", "SourceFile", "ParsedAt",
	}

	row := []string{
		pf.Executable,
		fmt.Sprint(pf.RunCount),
		fmt.Sprint(pf.FileSize),
		fmt.Sprint(pf.Version),
		fmt.Sprintf("%08X", pf.Hash),
		formatRunTimes(pf.LastRunTimes),
		strings.Join(pf.FilesAccessed, "|"),
		filepath.Base(file),
		file,
		time.Now().Format(time.RFC3339),
	}

	err = utils.SendCsvToWazuh(config, headers, [][]string{row})
	if err != nil {
		fmt.Printf("prefetch|Error sending CSV to Wazuh for file %s: %v\n", file, err)
	}
}


func formatRunTimes(times []time.Time) string {
	var result []string
	for _, t := range times {
		if !t.IsZero() {
			result = append(result, t.Format(time.RFC3339))
		}
	}
	return strings.Join(result, "|")
}
