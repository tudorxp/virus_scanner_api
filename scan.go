package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// perform_scan runs the "scanner" virus scanner/wrapper on "filename", with a configured timeout;
// it returns true, no error if the file is a virus (if the scanner returns an exit code of 1);
// false, no error if the file is not a virus (scanner returns an exit code of 0);
// or false and an error.
func perform_scan(scanner string, filename string, timeout time.Duration) (bool, error) {

	var is_virus bool
	const isVirusExitStatus = 1

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := exec.CommandContext(ctx, scanner, filename).CombinedOutput()

	// no error?
	if err == nil {
		return is_virus, nil // success
	}

	// timeout encountered?
	if ctx.Err() == context.DeadlineExceeded {
		return is_virus, fmt.Errorf("scan timeout exceeded: %s", err)
	}

	exitError, ok := err.(*exec.ExitError)

	// execution error?
	if !ok {
		return is_virus, fmt.Errorf("exec error: %s", err)
	}

	// non-zero exit code
	if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
		if status.ExitStatus() == isVirusExitStatus {
			is_virus = true
			return is_virus, nil
		}
		return is_virus, fmt.Errorf("unknown exit code: %v", status.ExitStatus())
	} else {
		return is_virus, fmt.Errorf("unknown error: %s", exitError)
	}

}

// tests that perform_scan is working properly, on a non-virus and a virus sample files
func test_perform_scan() error {

	var test_cases = []struct {
		content  string
		is_virus bool
	}{
		{`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`, true},
		{"I am not a virus", false},
	}

	for _, tc := range test_cases {

		//open temp file
		tmpfile, err := ioutil.TempFile(temp_folder, "vsapi_temp_")
		if err != nil {
			return fmt.Errorf("Error creating temp file: %s", err)
		}

		// lazy remove & ignore errors
		defer os.Remove(tmpfile.Name())

		if _, err := tmpfile.WriteString(tc.content); err != nil {
			return fmt.Errorf("Error writing to temp file: %s", err)
		}
		if err := tmpfile.Close(); err != nil {
			return fmt.Errorf("Error closing temp file: %s", err)
		}

		is_virus, err := perform_scan(conf.Scanner, tmpfile.Name(), conf.timeout)
		if err != nil {
			return fmt.Errorf("Error running perform_scan: %s", err)
		}

		if is_virus != tc.is_virus {
			return fmt.Errorf("Error: unexpected is_virus result from perform scan, got: %v, want: %v", is_virus, tc.is_virus)
		}

	}

	// success
	return nil
}
