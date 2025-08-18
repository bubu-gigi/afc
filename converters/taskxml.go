package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"encoding/xml"
	"fmt"
	"log"
	"os"
)

func ConvertTaskXmlToCsv(files []string, cfg *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		if err := convertTaskXml(file, cfg, opts); err != nil {
			log.Printf("taskxml: error processing file %s: %v", file, err)
		}
	}
}

func convertTaskXml(file string, cfg *config.Config, opts *flags.GlobalOptions) error {
	xmlFile, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("taskxml: open error: %w", err)
	}
	defer xmlFile.Close()

	var task Task
	decoder := xml.NewDecoder(xmlFile)
	if err := decoder.Decode(&task); err != nil {
		return fmt.Errorf("taskxml: xml decode error: %w", err)
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

	utils.HandleArtifactConverted(cfg, "taskxml", file, headers, [][]string{record}, opts)

	return nil
}
