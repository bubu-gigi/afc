package converters

import (
	"afc/config"
	utils "afc/lib"
	"bufio"
	"fmt"
	"os"
)

func ConvertPSHistoryToCsv(files []string, config *config.Config) {
	for _, file := range files {
		convertPSHistory(file, config)
	}
}

func convertPSHistory(file string, config *config.Config) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("powershell|Error opening file %s: %v\n", file, err)
		return
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
		fmt.Printf("powershell|Error scanning file %s: %v\n", file, err)
		return
	}

	err = utils.SendCsvToWazuh(config, headers, rows)
	if err != nil {
		fmt.Printf("powershell|Error sending CSV to Wazuh for file %s: %v\n", file, err)
	}
}
