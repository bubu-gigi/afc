package converters

import (
	utils "afc/lib"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	prefetch "www.velocidex.com/golang/go-prefetch"
)


func ConvertPrefetchToCsv(files []string) {
	for _, file := range files {
		convertPrefetch(file)
	}
}

func convertPrefetch(file string) {
	var f *os.File
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening the file")
		return
	}
	defer f.Close()

	pf, err := prefetch.LoadPrefetch(f)
	if err != nil {
		panic(err)
	}

	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()

	writer := csv.NewWriter(fileOut)
	defer writer.Flush()

	writer.Write([]string{
		"Executable", "RunCount", "FileSize", "Version", "Hash", "LastRunTimes", "FilesAccessed",
		"PrefetchFilename", "SourceFile", "ParsedAt",
	})

	writer.Write([]string{
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
	})
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
