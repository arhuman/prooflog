package client_test

import (
	"context"
	"fmt"
	"log"

	"github.com/arhuman/prooflog/client"
)

// ExampleClient_Send records an access-revocation event through the local
// prooflog agent. The subject identity goes in Actor (pseudonymized by the
// agent); detail goes in the encrypted Payload — never in the event Type.
func ExampleClient_Send() {
	c := client.New("127.0.0.1:9600")

	acc, err := c.Send(context.Background(), client.Event{
		Type:    client.EventAccessRevoked,
		Actor:   "admin@acme",
		Outcome: client.OutcomeSuccess,
		Payload: map[string]string{"user": "bob", "system": "vpn"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("accepted seq=%d type=%s\n", acc.Seq, acc.EventType)
}
