package converters

import (
	"afc/lib"
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

func ConvertEvtxToCsv(files []string) {
	for _, file := range files {
		convertEvtx(file)
	}
}

func convertEvtx(file string) {
	// open it
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("Error opening the file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// we get chunks of the file
	var chunks []*evtx.Chunk;
	chunks, _ = evtx.GetChunks(f)
	// map with k-v string
	var flattenedRecords []map[string]string
	// unique set for the headers of csv
	fieldSet := make(map[string]bool)
	// iterate over a single chunk
	for _, chunk := range chunks {
		// list of events
		var events []*evtx.EventRecord
		events, _ = chunk.Parse(0)
		// iterate over events
		for _, event := range events {
			// get a single event and map it to a Dict
			dict := event.Event.(*ordereddict.Dict)
			// new map
			row := make(map[string]string)
			flattenDict("", dict, row)
			flattenedRecords = append(flattenedRecords, row)
			// populate the headers
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

	// populate the csv headers
	shortHeaders := make([]string, len(fullKeys))
	for i, full := range fullKeys {
		parts := strings.Split(full, ".")
		shortHeaders[i] = parts[len(parts)-1]
	}
	// open the output file
	fileOut := utils.CreateOutputFile(file)
	defer fileOut.Close()
	
	writer := csv.NewWriter(fileOut)
	defer writer.Flush()
	// put the headers
	writer.Write(shortHeaders)

	for _, record := range flattenedRecords {
		var row []string
		for _, full := range fullKeys {
			row = append(row, record[full])
		}
		writer.Write(row)
	}
}

// rec func that dynamically populate a single csv row based on nested object
func flattenDict(prefix string, d *ordereddict.Dict, out map[string]string) {
	// iterate for every key of the dictionary
	for _, key := range d.Keys() {
		val, _ := d.Get(key)
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		// check the type whether is a primitive one or not
		switch v := val.(type) {
		case *ordereddict.Dict:
			flattenDict(fullKey, v, out)
		default:
			out[fullKey] = fmt.Sprintf("%v", v)
		}
	}
}

