package converters

import (
	utils "afc/lib"
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
)

func ConvertPSHistoryToCsv(files []string) {
	for _, file := range files {
		convertPSHistory(file)
	}
}

func convertPSHistory(file string) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening the file powershellHistory")
		os.Exit(1)
	}
	defer f.Close()

	output := utils.CreateOutputFile(file)
	defer output.Close()
	writer := csv.NewWriter(output)
	defer writer.Flush()
	writer.Write([]string{"LineNumber", "Command"})

	scanner := bufio.NewScanner(f)
	lineNum := 1
	for scanner.Scan() {
		writer.Write([]string{
			fmt.Sprintf("%d", lineNum),
			scanner.Text(),
		})
		lineNum++
	}
}