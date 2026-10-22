package main

import (
	"fmt"
	"net"
	"os"
)

// Run next to Envoy inside the Docker bridge. Docker Desktop's host gateway
// may discard empty UDP packets; the fixture must preserve every valid packet.
func main() {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:9005")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("udp-ready")
	buffer := make([]byte, 65535)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err = conn.WriteTo(buffer[:n], peer); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
