package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
#include <uapi/linux/ptrace.h>
#include <linux/string.h>

// create Table table events with function BPF_PERF_OUTPUT
BPF_PERF_OUTPUT(events);
inline int function_was_called(struct pt_regs *ctx) {
	char x[29] = "Hey, the handler was called!";
	// send the string into the table
	events.perf_submit(ctx, &x, sizeof(x));
	return 0;
}
`

func main() {
	// Create a module by passing the eBPF program text
	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	// Create a Uprobe(system call) to attach to the function
	uprobeFd, err := bpfModule.LoadUprobe("function_was_called")
	if err != nil {
		log.Fatal(err)
	}

	// Attach the Uprobe to the function
	err = bpfModule.AttachUprobe(os.Args[1], "main.handlerFunction", uprobeFd, -1)
	if err != nil {
		log.Fatal(err)
	}

	// Get the reference to the table created by the eBPF program
	table := bcc.NewTable(bpfModule.TableId("events"), bpfModule)
	rCh := make(chan []byte)
	lCh := make(chan uint64)

	// interface with the table by receiving data from receive channel
	perfMap, err := bcc.InitPerfMap(table, rCh, lCh)
	if err != nil {
		log.Fatal(err)
	}
	// start the perfMap
	perfMap.Start()
	defer perfMap.Stop()

	// receive data from receiveCh
	go func() {
		for {
			value := <-rCh
			fmt.Println(string(value))
		}
	}()

	// Stop if we receive an interruption signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
}
