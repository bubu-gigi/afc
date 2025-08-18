package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	prefetch "www.velocidex.com/golang/go-prefetch"
)

func ConvertPrefetchToCsv(files []string, cfg *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		if err := convertPrefetch(file, cfg, opts); err != nil {
			log.Printf("prefetch: failed to convert file %s: %v", file, err)
		}
	}
}

func convertPrefetch(file string, cfg *config.Config, opts *flags.GlobalOptions) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open error: %w", err)
	}
	defer f.Close()

	pf, err := prefetch.LoadPrefetch(f)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
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

	utils.HandleArtifactConverted(cfg, "prefetch", file, headers, [][]string{row}, opts.SkipWazuhSend)
	log.Printf("[INFO] Converted prefetch %s with %d records", file, len([][]string{row}))
	return nil
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
