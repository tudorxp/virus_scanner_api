//
// A virus scanner API implementation
//
// @tudorxp 2018
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

var logger = log.New(os.Stdout, "vsapi: ", log.Ldate|log.Ltime|log.Lshortfile)

type Config struct {
	Address string `json:"bind_address"`    // e.g. 127.0.0.1:8080
	Scanner string `json:"scanner_path"`    // e.g. /usr/local/bin/clamav
	Timeout string `json:"request_timeout"` // e.g. "30s"
	Threads int    `json:"threads"`         // e.g. 4
	timeout time.Duration
}

const temp_folder = "/tmp"

var conf Config

// Parses command line variables, loads the config file, and starts the web server
func main() {

	logger.Print("Starting up")

	// Define and parse command line flags
	config_filenamé := flag.String("config", "vsapi.conf", "Configuration file name")
	flag.Parse()

	var err error
	// Load and verify configuration
	conf, err = load_config(config_filenamé)
	if err != nil {
		logger.Fatalf("Error loading config: %s", err)
	}

	if conf.Address == "" {
		logger.Fatalf("Fatal: no bind address provided")
	}
	logger.Print(fmt.Sprintf("Binding on address: %s", conf.Address))
	logger.Printf("AV Scanner at: %s", conf.Scanner)

	if conf.Timeout == "" {
		conf.Timeout = "30s"
	}

	if conf.timeout, err = time.ParseDuration(conf.Timeout); err != nil {
		logger.Fatalf("Error parsing config duration %s: %s", conf.Timeout, err)
	} else {
		logger.Printf("Request timeout duration: %v", conf.timeout)
	}

	logger.Print("Testing virus scanner functionality...")
	if err := test_perform_scan(); err != nil {
		logger.Fatalf("error on test_perform_scan: %s", err)
	} else {
		logger.Print("all good.")
	}

	start_http_server()

}

func load_config(config_filename *string) (Config, error) {

	var conf Config

	fd, err := os.Open(*config_filename)
	if err != nil {
		return conf, err
	}

	// Lazily close file on any of the function exit paths
	defer fd.Close()

	// Create a new JSON decoder for the input stream - which can be anything that is capable of being read from
	js := json.NewDecoder(fd)
	if err = js.Decode(&conf); err != nil {
		return conf, fmt.Errorf("decoding json: %s", err)
	}

	return conf, nil
}
