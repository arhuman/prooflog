package main

import (
	"fmt"

	"github.com/arhuman/prooflog/internal/spool"
)

// runSpool dispatches spool subcommands. Only "cat" exists in this phase.
func runSpool(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prooflog spool cat <dir>")
	}
	switch args[0] {
	case "cat":
		return runSpoolCat(args[1:])
	default:
		return fmt.Errorf("unknown spool subcommand %q (want: cat)", args[0])
	}
}

// runSpoolCat pretty-prints every frame in a spool directory (§4.4).
func runSpoolCat(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prooflog spool cat <dir>")
	}
	dir := args[0]

	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		return err
	}
	defer sp.Close()

	it, err := sp.Iter(0)
	if err != nil {
		return err
	}
	defer it.Close()

	var n uint64
	for {
		rec, ok, err := it.Next()
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		n++
		payload := "encrypted"
		if rec.IsSystem() {
			payload = "clear:" + string(rec.PayloadClear)
		}
		fmt.Printf("seq=%-6d %-28s %s actor=%q outcome=%q\n",
			rec.Seq, rec.EventType, rec.EventTime, rec.Actor, rec.Outcome)
		fmt.Printf("        hash=%s prev=%s\n", rec.HashHex(), rec.PrevHash)
		fmt.Printf("        payload=%s\n", payload)
	}
	fmt.Printf("\n%d frame(s), last acked seq=%d, last seq=%d\n", n, sp.AckedSeq(), sp.LastSeq())
	return nil
}
