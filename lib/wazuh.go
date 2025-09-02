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

type FileMetadata struct {
    Filename   string `json:"filename"`
    Abspath    string `json:"abspath"`
    Size       int64  `json:"size"`
    ModTime    string `json:"modtime"`
    SHA256     string `json:"sha256"`
    Mode       string `json:"mode"`
    ModeOctal  string `json:"mode_octal"`
    IsSymlink  bool   `json:"is_symlink"`
    LinkTarget string `json:"link_target,omitempty"`
    IsDir      bool   `json:"is_dir"`
}

func SendToWazuh(cfg *config.Config, filePath string, headers []string, rows [][]string, saveBodyRequests bool) error {
    client := &http.Client{}
    if !cfg.Wazuh.VerifySSL {
        tr := &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        client.Transport = tr
    }

    url := fmt.Sprintf("%s://%s:%d%s?pretty=true&wait_for_complete=true",
        cfg.Wazuh.Protocol, cfg.Wazuh.ManagerIP, cfg.Wazuh.Port, cfg.Wazuh.Endpoint)

    if saveBodyRequests {
        if err := os.MkdirAll("body", os.ModePerm); err != nil {
            log.Printf("file|error creating body dir: %v", err)
        }
    }

   	if meta, err := getFileMetadata(filePath); err != nil {
		log.Printf("file|error extracting file metadata: %v", err)
	} else if jb, e := json.MarshalIndent(meta, "", "  "); e == nil {
		log.Printf("ℹ️ lstat metadata for %q:\n%s", filePath, string(jb))
	}

    // Costruzione eventi come stringhe
    var events []string
    for idx, row := range rows {
        if len(row) != len(headers) {
            log.Printf("csv|warning: riga %d ha lunghezza diversa dai headers, saltata", idx)
            continue
        }

        event := make(map[string]string)
        for i, h := range headers {
            event[h] = row[i]
        }

        eventBytes, err := json.Marshal(event)
        if err != nil {
            log.Printf("json|error marshalling event at row %d: %v", idx, err)
            continue
        }
        events = append(events, string(eventBytes))
    }

    batches := chunkEvents(events, 100)

    for batchIdx, batch := range batches {
        payload := map[string]any{"events": batch}

        body, err := json.MarshalIndent(payload, "", "  ")
        if err != nil {
            return fmt.Errorf("json|error building payload: %w", err)
        }

        if saveBodyRequests {
            fileName := fmt.Sprintf("body/batch_%d.json", batchIdx)
            if err := os.WriteFile(filepath.Clean(fileName), body, 0644); err != nil {
                log.Printf("file|error saving body to file: %v", err)
            }
        }

        req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
        if err != nil {
            return fmt.Errorf("http|error creating request: %w", err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", "Bearer "+cfg.Wazuh.Token)

        resp, err := client.Do(req)
        if err != nil {
            return fmt.Errorf("http|error sending request: %w", err)
        }
        defer resp.Body.Close()

        respBody, _ := io.ReadAll(resp.Body)

        switch resp.StatusCode {
        case 200, 201, 202:
            log.Printf("✅ Batch %d sent successfully", batchIdx)
        case 400:
            log.Printf("❌ [400 Bad Request] Batch %d: %s", batchIdx, string(respBody))
        case 401:
            log.Printf("❌ [401 Unauthorized] Batch %d: Token mancante o invalido.\n%s", batchIdx, string(respBody))
        case 403:
            log.Printf("❌ [403 Forbidden] Batch %d: Permessi mancanti. Consulta la documentazione RBAC.\n%s", batchIdx, string(respBody))
        case 405:
            log.Printf("❌ [405 Method Not Allowed] Batch %d: Metodo HTTP errato.\n%s", batchIdx, string(respBody))
        case 406:
            log.Printf("❌ [406 Not Acceptable] Batch %d: Tipo di body errato.\n%s", batchIdx, string(respBody))
        case 413:
            log.Printf("❌ [413 Payload Too Large] Batch %d: Payload troppo grande (> 1MB).\n%s", batchIdx, string(respBody))
        case 429:
            log.Printf("❌ [429 Too Many Requests] Batch %d: Limite di richieste raggiunto.\n%s", batchIdx, string(respBody))
        default:
            log.Printf("❌ [HTTP %d] Batch %d: %s", resp.StatusCode, batchIdx, string(respBody))
        }
    }

    return nil
}

func chunkEvents(events []string, maxSize int) [][]string {
	var batches [][]string
	for maxSize < len(events) {
		events, batches = events[maxSize:], append(batches, events[0:maxSize:maxSize])
	}
	batches = append(batches, events)
	return batches
}
func getFileMetadata(path string) (FileMetadata, error) {
    absPath, err := filepath.Abs(path)
    if err != nil {
        return FileMetadata{}, err
    }

    info, err := os.Lstat(path) // 👈 NON segue i symlink
    if err != nil {
        return FileMetadata{}, err
    }

    md := FileMetadata{
        Filename:  info.Name(),
        Abspath:   absPath,
        Size:      info.Size(),
        ModTime:   info.ModTime().Format(time.RFC3339),
        Mode:      info.Mode().String(),
        ModeOctal: fmt.Sprintf("%#o", uint32(info.Mode().Perm())),
        IsSymlink: info.Mode()&os.ModeSymlink != 0,
        IsDir:     info.IsDir(),
    }

    // Se è un symlink, leggi il target ma NON calcolare l'hash
    if md.IsSymlink {
        if target, e := os.Readlink(path); e == nil {
            md.LinkTarget = target
        }
        return md, nil
    }

    // Calcola SHA256 solo per file regolari
    if info.Mode().IsRegular() {
        f, err := os.Open(path)
        if err != nil {
            return md, err
        }
        defer f.Close()

        hasher := sha256.New()
        if _, err := io.Copy(hasher, f); err != nil {
            return md, err
        }
        md.SHA256 = fmt.Sprintf("%x", hasher.Sum(nil))
    }
    return md, nil
}
