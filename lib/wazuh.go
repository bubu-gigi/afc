package utils

import (
	"afc/config"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Wazuh struct {
		ManagerIP string `yaml:"manager_ip"`
		Port      int    `yaml:"port"`
		Protocol  string `yaml:"protocol"`
		Endpoint  string `yaml:"endpoint"`
		Token     string `yaml:"token"`
		VerifySSL bool   `yaml:"verify_ssl"`
	} `yaml:"wazuh"`

	Paths struct {
		Input string `yaml:"input"`
	} `yaml:"paths"`
}

type FileMetadata struct {
	Filename   string `json:"filename"`
	Abspath    string `json:"abspath"`
	Size       int64  `json:"size"`
	ModTime    string `json:"modtime"`     
	SHA256     string `json:"sha256"`       
	Mode       string `json:"mode"`         
	IsSymlink  bool   `json:"is_symlink"`   
}

func SendCsvToWazuh(cfg *config.Config, headers []string, rows [][]string) error {
	const (
		maxEventsPerRequest  = 100
		maxRequestsPerMinute = 30
		sleepPerRequest      = time.Minute / maxRequestsPerMinute
	)

	client := &http.Client{}
	if !cfg.Wazuh.VerifySSL {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}

	url := fmt.Sprintf("%s://%s:%d%s?pretty=true&wait_for_complete=true",
		cfg.Wazuh.Protocol, cfg.Wazuh.ManagerIP, cfg.Wazuh.Port, cfg.Wazuh.Endpoint)

	if err := os.MkdirAll("body", os.ModePerm); err != nil {
		log.Printf("file|error creating body dir: %v", err)
	}

		metadata, err := getFileMetadata(cfg.Paths.Input)
	if err != nil {
		log.Printf("file|error extracting file metadata: %v", err)
	}

	var events []map[string]any
	for idx, row := range rows {
		if len(row) != len(headers) {
			log.Printf("csv|warning: riga %d ha lunghezza diversa dai headers, saltata", idx)
			continue
		}
		event := make(map[string]string)
		for i, h := range headers {
			event[h] = row[i]
		}
		events = append(events, map[string]interface{}{
			"event":    event,
			"metadata": metadata,
		})
	}

	for i := 0; i < len(events); i += maxEventsPerRequest {
		end := i + maxEventsPerRequest
		if end > len(events) {
			end = len(events)
		}

		var eventStrings []string
		for _, e := range events[i:end] {
			encoded, err := json.Marshal(e)
			if err != nil {
				log.Printf("json|error encoding single event: %v", err)
				continue
			}
			eventStrings = append(eventStrings, string(encoded))
		}

		payload := map[string]interface{}{
			"events": eventStrings,
		}

		body, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			log.Printf("json|error building payload batch %d-%d: %v", i, end, err)
			continue
		}

		fileName := fmt.Sprintf("body/batch_%d_%d.json", i, end)
		if err := os.WriteFile(filepath.Clean(fileName), body, 0644); err != nil {
			log.Printf("file|error saving batch %d-%d to file: %v", i, end, err)
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
		if err != nil {
			log.Printf("http|error creating request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.Wazuh.Token)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("http|error sending batch %d-%d: %v", i, end, err)
			continue
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)

		switch resp.StatusCode {
		case 200, 201, 202:
			log.Printf("✅ Batch %d-%d sent successfully", i, end)
		case 400:
			log.Printf("❌ [400 Bad Request] Batch %d-%d: %s", i, end, string(respBody))
		case 401:
			log.Printf("❌ [401 Unauthorized] Batch %d-%d: Token mancante o invalido.\n%s", i, end, string(respBody))
		case 403:
			log.Printf("❌ [403 Forbidden] Batch %d-%d: Permessi mancanti. Consulta la documentazione RBAC.\n%s", i, end, string(respBody))
		case 405:
			log.Printf("❌ [405 Method Not Allowed] Batch %d-%d: Metodo HTTP errato.\n%s", i, end, string(respBody))
		case 406:
			log.Printf("❌ [406 Not Acceptable] Batch %d-%d: Tipo di body errato.\n%s", i, end, string(respBody))
		case 413:
			log.Printf("❌ [413 Payload Too Large] Batch %d-%d: Payload troppo grande (> 1MB).\n%s", i, end, string(respBody))
		case 429:
			log.Printf("❌ [429 Too Many Requests] Batch %d-%d: Limite di richieste raggiunto.\n%s", i, end, string(respBody))
		default:
			log.Printf("❌ [HTTP %d] Batch %d-%d: %s", resp.StatusCode, i, end, string(respBody))
		}

		time.Sleep(sleepPerRequest)
	}

	return nil
}

func getFileMetadata(path string) (FileMetadata, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return FileMetadata{}, err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return FileMetadata{}, err
	}

	f, err := os.Open(path)
	if err != nil {
		return FileMetadata{}, err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return FileMetadata{}, err
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	return FileMetadata{
		Filename:  info.Name(),
		Abspath:   absPath,
		Size:      info.Size(),
		ModTime:   info.ModTime().Format(time.RFC3339),
		SHA256:    hash,
		Mode:      info.Mode().String(),
		IsSymlink: info.Mode()&os.ModeSymlink != 0,
	}, nil
}
