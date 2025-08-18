package converters

import (
	"afc/config"
	"afc/flags"
	utils "afc/lib"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

var fieldsToShorten = map[string]bool{
	"RecordNumber":    true,
	"EventRecordID":   true,
	"TimeCreated":     true,
	"EventID":         true,
	"Level":           true,
	"Provider":        true,
	"Channel":         true,
	"ProcessId":       true,
	"ThreadId":        true,
	"Computer":        true,
	"ChunkNumber":     true,
	"UserId":          true,
	"MapDescription":  true,
	"UserName":        true,
	"RemoteHost":      true,
	"PayloadData1":    true,
	"PayloadData2":    true,
	"PayloadData3":    true,
	"PayloadData4":    true,
	"PayloadData5":    true,
	"PayloadData6":    true,
	"ExecutableInfo":  true,
	"HiddenRecord":    true,
	"SourceFile":      true,
	"Keywords":        true,
	"ExtraDataOffset": true,
	"Payload":         true,
}

func ConvertEvtxToCsv(files []string, config *config.Config, opts *flags.GlobalOptions) {
	for _, file := range files {
		if err := convertEvtx(file, config, opts); err != nil {
			log.Printf("[ERROR] Failed to convert EVTX file %s: %v", file, err)
		}
	}
}

func convertEvtx(file string, config *config.Config, opts *flags.GlobalOptions) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot open EVTX file %s: %w", file, err)
	}
	defer f.Close()

	chunks, err := evtx.GetChunks(f)
	if err != nil {
		return fmt.Errorf("cannot extract chunks from EVTX file %s: %w", file, err)
	}

	var flattenedRecords []map[string]string
	fieldSet := make(map[string]bool)
	recordCount := 0

	for chunkIndex, chunk := range chunks {
		events, err := chunk.Parse(0)
		if err != nil {
			log.Printf("[WARNING] Failed to parse chunk %d in file %s: %v", chunkIndex, file, err)
			continue
		}

		for _, event := range events {
			dict, ok := event.Event.(*ordereddict.Dict)
			if !ok {
				continue
			}

			recordCount++
			row := make(map[string]string)

			row["RecordNumber"] = strconv.Itoa(recordCount)
			row["ChunkNumber"] = fmt.Sprintf("%d", chunkIndex)
			row["EventRecordID"] = fmt.Sprintf("%d", event.Header.RecordID)
			row["TimeCreated"] = utils.FileTimeToString(event.Header.FileTime)
			row["SourceFile"] = file

			flattenDict("", dict, row)

			row["EventID"] = row["System.EventID"]
			row["Provider"] = row["System.Provider.Name"]
			row["Computer"] = row["System.Computer"]
			row["Channel"] = row["System.Channel"]
			row["ProcessId"] = row["System.Execution.ProcessID"]
			row["ThreadId"] = row["System.Execution.ThreadID"]
			row["Keywords"] = row["System.Keywords"]

			if levelVal, ok := row["System.Level"]; ok {
				row["Level"] = TranslateLevel(levelVal)
			}

			domain := row["Event.EventData.SubjectDomainName"]
			name := row["Event.EventData.SubjectUserName"]
			sid := row["Event.EventData.SubjectUserSid"]
			if domain != "" && name != "" && sid != "" {
				row["UserName"] = fmt.Sprintf("%s\\%s (%s)", domain, name, sid)
			}

			row["ExecutableInfo"] = row["Event.EventData.CallerProcessName"]

			for i := 0; i < 6; i++ {
				row[fmt.Sprintf("PayloadData%d", i+1)] = extractPayloadDataN(dict, i)
			}

			if payloadBytes, err := json.Marshal(dict); err == nil {
				row["Payload"] = string(payloadBytes)
			}

			flattenedRecords = append(flattenedRecords, row)

			for k := range row {
				fieldSet[k] = true
			}
		}
	}

	var fullKeys []string
	for k := range fieldSet {
		fullKeys = append(fullKeys, k)
	}
	sort.Strings(fullKeys)

	shortKeys := make([]string, len(fullKeys))
	for i, k := range fullKeys {
		parts := strings.Split(k, ".")
		lastPart := parts[len(parts)-1]
		if fieldsToShorten[lastPart] {
			shortKeys[i] = lastPart
		} else {
			shortKeys[i] = k
		}
	}

	var allRows [][]string
	for _, record := range flattenedRecords {
		var row []string
		for _, k := range fullKeys {
			row = append(row, record[k])
		}
		allRows = append(allRows, row)
	}

	utils.HandleArtifactConverted(config, "evtx", file, shortKeys, allRows, opts.SkipWazuhSend)
	log.Printf("[INFO] Converted %d events from file %s", recordCount, file)
	return nil
}

func flattenDict(prefix string, d *ordereddict.Dict, out map[string]string) {
	for _, key := range d.Keys() {
		val, _ := d.Get(key)
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		switch v := val.(type) {
		case *ordereddict.Dict:
			flattenDict(fullKey, v, out)
		case []interface{}:
			for i, elem := range v {
				switch sub := elem.(type) {
				case *ordereddict.Dict:
					flattenDict(fmt.Sprintf("%s[%d]", fullKey, i), sub, out)
				default:
					out[fmt.Sprintf("%s[%d]", fullKey, i)] = fmt.Sprintf("%v", sub)
				}
			}
		default:
			out[fullKey] = fmt.Sprintf("%v", v)
		}
	}
}

func extractPayloadDataN(dict *ordereddict.Dict, index int) string {
	if ed, ok := dict.Get("EventData"); ok {
		if edict, ok := ed.(*ordereddict.Dict); ok {
			if dataArray, ok := edict.Get("Data"); ok {
				if dataSlice, ok := dataArray.([]interface{}); ok && index < len(dataSlice) {
					if d, ok := dataSlice[index].(*ordereddict.Dict); ok {
						if txt, ok := d.Get("#text"); ok {
							return fmt.Sprintf("%v", txt)
						}
					}
				}
			}
		}
	}
	return ""
}

func TranslateLevel(level string) string {
	switch level {
	case "0":
		return "LogAlways"
	case "1":
		return "Critical"
	case "2":
		return "Error"
	case "3":
		return "Warning"
	case "4":
		return "Information"
	case "5":
		return "Verbose"
	default:
		return "Unknown"
	}
}
