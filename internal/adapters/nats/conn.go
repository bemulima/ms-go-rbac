package nats

import (
	natsgo "github.com/nats-io/nats.go"
)

// Connect establishes a NATS connection.
func Connect(url string) (*natsgo.Conn, error) {
	return natsgo.Connect(url)
}
