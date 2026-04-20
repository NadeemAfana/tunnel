package main

import (
	"io"
	"os"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

// TestMain silences logrus output for the whole test binary by default.
// Set TEST_LOG=1 to restore normal logging when debugging a failing test.
func TestMain(m *testing.M) {
	if os.Getenv("TEST_LOG") == "" {
		log.SetOutput(io.Discard)
	}
	os.Exit(m.Run())
}

func TestValidation(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tunnel main suite")
}
