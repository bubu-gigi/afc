package main

import (
	"os"
	"gopkg.in/yaml.v2"
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


func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	return &cfg, err
}
