package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
BPF_PERF_OUTPUT(events);
int hello(void *ctx) {
	char x[29] = "Hello";
	events.perf_submit(ctx, &x, sizeof(x));
	return 0;
}
`

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	kprobeFd, err := bpfModule.LoadKprobe("function_was_called")
	if err != nil {
		log.Fatal(err)
	}

	err = bpfModule.AttachKprobe("sys_execve", kprobeFd, 1)
	handleErr(err)

	table := bcc.NewTable(bpfModule.TableId("events"), bpfModule)
	rCh := make(chan []byte)
	lCh := make(chan uint64)

	perfMap, err := bcc.InitPerfMap(table, rCh, lCh)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			value := <-rCh
			fmt.Println(string(value))
		}
	}()

	perfMap.Start()
	<-sigCh
	perfMap.Stop()
	fmt.Println("")
	fmt.Println("End")
}

func handleErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
