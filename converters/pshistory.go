package converters

import (
	"afc/config"
	utils "afc/lib"
	"bufio"
	"fmt"
	"log"
	"os"
)

func ConvertPSHistoryToCsv(files []string, config *config.Config) {
	for _, file := range files {
		if err := convertPSHistory(file, config); err != nil {
			log.Printf("powershell: failed to convert file %s: %v", file, err)
		}
	}
}

func convertPSHistory(file string, config *config.Config) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("open error: %w", err)
	}
	defer f.Close()

	headers := []string{"LineNumber", "Command"}
	var rows [][]string

	scanner := bufio.NewScanner(f)
	lineNum := 1
	for scanner.Scan() {
		rows = append(rows, []string{
			fmt.Sprintf("%d", lineNum),
			scanner.Text(),
		})
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	if err := utils.SendCsvToWazuh(config, headers, rows); err != nil {
		return fmt.Errorf("send to Wazuh failed: %w", err)
	}

	return nil
}
