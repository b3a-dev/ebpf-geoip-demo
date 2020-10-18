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

BPF_PERF_OUTPUT(events);

inline int function_was_called(struct pt_regs *ctx) {

	char x[29] = "Hey, new request received!";
	events.perf_submit(ctx, &x, sizeof(x));
	return 0;
}
`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	uprobeFd, err := bpfModule.LoadUprobe("function_was_called")
	if err != nil {
		log.Fatal(err)
	}

	//  AttachUprobe attaches a uprobe fd to the symbol in the library or binary 'name'
	// The 'name' argument can be given as either a full library path (/usr/lib/..), a library without the lib prefix,
	// or as a binary with full path (/bin/bash) A pid can be given to attach to, or -1 to attach to all processes
	err = bpfModule.AttachUprobe(os.Args[1], "main.respond", uprobeFd, -1)
	if err != nil {
		log.Fatal(err)
	}

	lostChan := make(chan uint64)
	table := bcc.NewTable(bpfModule.TableId("events"), bpfModule)
	channel := make(chan []byte)

	// InitPerfMap initializes a perf map with a receiver channel, with a default page_cnt.
	// func InitPerfMap(table *Table, receiverChan chan []byte, lostChan chan uint64) (*PerfMap, error)
	perfMap, err := bcc.InitPerfMap(table, channel, lostChan)

	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for {
			value := <-channel
			fmt.Println(string(value))
		}
	}()

	perfMap.Start()
	<-c
	perfMap.Stop()
}
