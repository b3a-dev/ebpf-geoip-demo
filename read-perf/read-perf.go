package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func main() {
	path := "/sys/fs/bpf/tc/globals/xevents"
	eventsMap, err := ebpf.LoadPinnedMap(path)
	if err != nil {
		log.Fatal("failed to load xevents: ", err)
	}

	fmt.Printf("MaxEntries=%d\n", eventsMap.ABI().MaxEntries)
	bufferSize := int(4096 * eventsMap.ABI().MaxEntries)
	eventsRd, err := perf.NewReader(eventsMap, bufferSize)
	if err != nil {
		log.Fatal("Failed to initialize perf ring buffer:", err)
	}
	defer eventsRd.Close()

	for {
		rec, err := eventsRd.Read()
		if err != nil {
			break
		}
		ip4 := net.IPv4(
			rec.RawSample[0],
			rec.RawSample[1],
			rec.RawSample[2],
			rec.RawSample[3],
		)
		fmt.Printf("->%s\n", ip4)
	}
}
