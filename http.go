package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type empty struct{}

var scan_semaphore chan empty

func start_http_server() {

	// Register HTTP handlers
	http.HandleFunc("/scan", scan_request_handler)

	// Create limited capacity semaphore
	scan_semaphore = make(chan empty, conf.Threads)

	logger.Print("Starting up HTTP server")
	logger.Fatal(http.ListenAndServe(conf.Address, nil))
}

func scan_request_handler(w http.ResponseWriter, r *http.Request) {

	start_time := time.Now()
	logger.Printf("%v: New connection from: %v ", start_time.Format(time.StampNano), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")

	timeout_channel := time.After(conf.timeout)

	select {

	case  <-timeout_channel:
		// We've hit the timeout!
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{ "error" : "Timed out after %s" }`+"\n", conf.timeout)
		logger.Printf("%v: Timed out, returning", start_time.Format(time.StampNano))
		return

	case scan_semaphore <- empty{}:
		// Got a slot to run the scanner, continue normal flow of execution
	}

	defer func() { <-scan_semaphore }() // Vacate slot at the end of function

	logger.Printf("%v: Received run slot after %v", start_time.Format(time.StampNano), time.Since(start_time))
	remaining_timeout := conf.timeout - time.Since(start_time)

	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(w, `{ "error" : "Method not allowed!" }`)
		return
	}

	//open temp file
	tmpfile, err := ioutil.TempFile(temp_folder, "vsapi_temp_")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{ "error" : "Error creating temp file: %s" }`+"\n", err)
		logger.Printf("%v: Error creating temp file: %s", start_time.Format(time.StampNano), err)
		return
	}

	// lazy remove & ignore errors
	defer os.Remove(tmpfile.Name())

	if _, err := io.Copy(tmpfile, r.Body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{ "error" : "Error writing to temp file: %s" }`+"\n", err)
		logger.Printf("%v: Error writing to temp file: %s", start_time.Format(time.StampNano), err)

		return
	}
	if err := tmpfile.Close(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{ "error" : "Error closing temp file: %s" }`+"\n", err)
		logger.Printf("%v: Error closing temp file: %s", start_time.Format(time.StampNano), err)
		return
	}

	logger.Printf("%v: Running scanner with a timeout of: %v", start_time.Format(time.StampNano), remaining_timeout)

	is_virus, err := perform_scan(conf.Scanner, tmpfile.Name(), remaining_timeout)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{ "error" : "Error running perform_scan: %s" }`+"\n", err)
		logger.Printf("%v: Error running perform_scan: %s", start_time.Format(time.StampNano), err)
		return
	}

	if is_virus {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{ "is_virus" : true }`)
		logger.Printf("%v: Found virus", start_time.Format(time.StampNano))
		return
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{ "is_virus" : false }`)
		logger.Printf("%v: Did not find virus", start_time.Format(time.StampNano))
		return
	}

}
