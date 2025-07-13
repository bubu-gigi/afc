package converters

import (
	"afc/config"
	utils "afc/lib"
	"encoding/xml"
	"fmt"
	"os"
)

func ConvertTaskXmlToCsv(files []string, config *config.Config) {
	for _, file := range files {
		err := convertTaskXml(file, config)
		if err != nil {
			fmt.Printf("Errore nel file %s: %v\n", file, err)
		}
	}
}
func convertTaskXml(file string, config *config.Config) error {
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

	headers := []string{
		"File", "Author", "UserID", "LogonType",
		"Command", "Arguments", "TriggerStart", "TriggerEnabled",
	}

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

	record := []string{
		file,
		task.Registration.Author,
		principal,
		logon,
		command,
		args,
		triggerStart,
		triggerEnabled,
	}

	err = utils.SendCsvToWazuh(config, headers, [][]string{record})
	if err != nil {
		return fmt.Errorf("errore invio Wazuh: %w", err)
	}

	return nil
}
