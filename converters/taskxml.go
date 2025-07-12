package converters

import (
	utils "afc/lib"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"os"
)

func ConvertTaskXmlToCsv(files []string) {
	for _, file := range files {
		err := convertTaskXml(file)
		if err != nil {
			fmt.Printf("Errore nel file %s: %v\n", file, err)
		}
	}
}

func convertTaskXml(file string) error {
	xmlFile, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("errore apertura file: %w", err)
	}
	defer xmlFile.Close()

	var task Task
	decoder := xml.NewDecoder(xmlFile)
	err = decoder.Decode(&task)
	if err != nil {
		return fmt.Errorf("errore parsing XML: %w", err)
	}

	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()

	writer := csv.NewWriter(fileOut)
	defer writer.Flush()

	writer.Write([]string{
		"File", "Author", "UserID", "LogonType",
		"Command", "Arguments", "TriggerStart", "TriggerEnabled",
	})

	principal := ""
	logon := ""
	if len(task.Principals.Principal) > 0 {
		principal = task.Principals.Principal[0].UserID
		logon = task.Principals.Principal[0].LogonType
	}

	command := ""
	args := ""
	if len(task.Actions.Exec) > 0 {
		command = task.Actions.Exec[0].Command
		args = task.Actions.Exec[0].Arguments
	}

	triggerStart := ""
	triggerEnabled := ""
	if len(task.Triggers.TimeTrigger) > 0 {
		triggerStart = task.Triggers.TimeTrigger[0].StartBoundary
		triggerEnabled = task.Triggers.TimeTrigger[0].Enabled
	}

	writer.Write([]string{
		file,
		task.Registration.Author,
		principal,
		logon,
		command,
		args,
		triggerStart,
		triggerEnabled,
	})

	return nil
}