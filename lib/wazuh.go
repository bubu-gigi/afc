package utils

import (
	"afc/config"
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
)

type Config struct {
	Wazuh struct {
		ManagerIP  string `yaml:"manager_ip"`
		Port       int    `yaml:"port"`
		Protocol   string `yaml:"protocol"`
		Endpoint   string `yaml:"endpoint"`
		Token      string `yaml:"token"`
		VerifySSL  bool   `yaml:"verify_ssl"`
	} `yaml:"wazuh"`

	Paths struct {
		Input  string `yaml:"input"`
	} `yaml:"paths"`
}

func SendCsvToWazuh(cfg *config.Config, headers []string, rows [][]string) error {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	writer.UseCRLF = true

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("csv|error writing headers: %w", err)
	}
	if err := writer.WriteAll(rows); err != nil {
		return fmt.Errorf("csv|error writing rows: %w", err)
	}
	writer.Flush()

	url := fmt.Sprintf("%s://%s:%d%s", cfg.Wazuh.Protocol, cfg.Wazuh.ManagerIP, cfg.Wazuh.Port, cfg.Wazuh.Endpoint)

	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return fmt.Errorf("http|error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "text/csv")
	req.Header.Set("Authorization", "Bearer "+cfg.Wazuh.Token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http|error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("http|error: received status %d", resp.StatusCode)
	}

	log.Printf("CSV sent successfully to %s", url)
	return nil
}
