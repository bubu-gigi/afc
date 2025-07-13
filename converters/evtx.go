package converters

import (
	"afc/config"
	utils "afc/lib"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

func ConvertEvtxToCsv(files []string, config *config.Config) {
	for _, file := range files {
		if err := convertEvtx(file, config); err != nil {
			log.Printf("evtx|Error converting file %s: %v", file, err)
		}
	}
}

func convertEvtx(file string, config *config.Config) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("evtx|Error opening file %s: %w", file, err)
	}
	defer f.Close()

	chunks, err := evtx.GetChunks(f)
	if err != nil {
		return fmt.Errorf("evtx|Error getting chunks from file %s: %w", file, err)
	}

	var flattenedRecords []map[string]string
	fieldSet := make(map[string]bool)

	for _, chunk := range chunks {
		events, err := chunk.Parse(0)
		if err != nil {
			log.Printf("evtx|Error parsing chunk in file %s: %v", file, err)
			continue
		}

		for _, event := range events {
			dict, ok := event.Event.(*ordereddict.Dict)
			if !ok {
				log.Printf("evtx|Unexpected event type in file %s: %T", file, event.Event)
				continue
			}

			row := make(map[string]string)
			flattenDict("", dict, row)
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

	// Headers semplificati
	shortHeaders := make([]string, len(fullKeys))
	for i, full := range fullKeys {
		parts := strings.Split(full, ".")
		shortHeaders[i] = parts[len(parts)-1]
	}

	// Prepara i dati da inviare
	var allRows [][]string
	for _, record := range flattenedRecords {
		var row []string
		for _, full := range fullKeys {
			row = append(row, record[full])
		}
		allRows = append(allRows, row)
	}

	err = utils.SendCsvToWazuh(config, shortHeaders, allRows)
	if err != nil {
		return fmt.Errorf("evtx|error sending CSV to Wazuh: %w", err)
	}

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
		default:
			out[fullKey] = fmt.Sprintf("%v", v)
		}
	}
}
