package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
#include <uapi/linux/ptrace.h>
#include <linux/string.h>


#define SP_OFFSET(offset) (void *)PT_REGS_SP(ctx) + offset * 8

struct str_arg {
	unsigned short len;
	char parameter_value[256];
}__attribute__((packed));

BPF_PERF_OUTPUT(events);

int get_arguments(struct pt_regs *ctx) {
	struct str_arg arg;
	char *parameter_value;
    
	bpf_probe_read(&parameter_value, sizeof(parameter_value), SP_OFFSET(1));
	bpf_probe_read(&arg.len, sizeof(arg.len), SP_OFFSET(2));
	bpf_probe_read_str(&arg.parameter_value, sizeof(arg.parameter_value), (void *)parameter_value);

	events.perf_submit(ctx, &arg, sizeof(arg));

	return 0;
}
`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	uprobeFd, err := bpfModule.LoadUprobe("get_arguments")
	if err != nil {
		log.Fatal(err)
	}

	//  AttachUprobe attaches a uprobe fd to the symbol in the library or binary 'name'
	// The 'name' argument can be given as either a full library path (/usr/lib/..), a library without the lib prefix,
	// or as a binary with full path (/bin/bash) A pid can be given to attach to, or -1 to attach to all processes
	err = bpfModule.AttachUprobe(os.Args[1], "main.postWord", uprobeFd, -1)
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
			argument := strings.Split(string(value), " ")
			word := argument[0]
			fmt.Println(word)
		}
	}()

	perfMap.Start()
	<-c
	perfMap.Stop()

	// Serve static files (index.html) for client side in browser
	http.Handle("/", http.FileServer(http.Dir("./static")))

	// Word Cloud chart in index.html will call /data.json to read data
	http.HandleFunc("/wordCloudData.json", wordcloudDataHandler)

	log.Println("Listening on :80...")
	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Fatal(err)
	}
}

// wordcloudDataHandler writes the json body needed to draw in the word cloud (index.html)

// The returned object needs to be an array of:
// name: Name of the country
// id: country ID
// percent: percent of the total requests in that country
// amount: number requests in that country
func wordcloudDataHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	points := []mapPoint{}
	for country, amount := range requestsByCountry {
		point := mapPoint{
			Name:    country,
			ID:      country,
			Amount:  strconv.Itoa(amount),
			Percent: fmt.Sprintf("%f", (float64(amount)/float64(requestsTotal))*100),
		}
		points = append(points, point)

	}
	str, _ := json.Marshal(points)
	fmt.Fprintf(w, string(str))
}
