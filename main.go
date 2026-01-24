package main

import (
	"log"
	"os"

	"github.com/denizsincar29/schat/internal/server"
)

func main() {
	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
		os.Exit(1)
	}
}
