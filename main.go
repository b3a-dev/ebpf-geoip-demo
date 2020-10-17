package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/abh/geoip"
)

// File containing GeoIP Lite database (Maxmind)
const geoIPFile = "GeoIP.dat"

// mapPoint is used to create a point in the Javascript map
type mapPoint struct {

	// Name of the country
	Name string `json:"name"`

	// ID is the country code of the country
	ID string `json:"id"`

	// Percentage of the requests for this point
	Percent string `json:"percent"`

	// Number of requests for this point
	Amount string `json:"amount"`
}

// For GeoIP to work you need to have GeoIP lib installed in the system
// as this Go lib is just a wrapper
var gi *geoip.GeoIP

// requestsByCountry contains request counter for each country
var requestsByCountry map[string]int

// requestsTotal contains counter of total requests
var requestsTotal int

// A request is described as a string with the source IPv4 Address
var requests chan string

func main() {

	var err error

	requests = make(chan string)
	requestsByCountry = make(map[string]int)
	go readRequests()

	gi, err = geoip.Open(geoIPFile)
	if err != nil {
		log.Fatalln("Could not open GeoIP database")
	}
		
	// eBPF map
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

	go func() {
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
			//fmt.Printf("->%s\n", ip4.String())
			requests <- ip4.String()
		}

	}()

	// Serve static files (index.html) for client side in browser
	http.Handle("/", http.FileServer(http.Dir("./static")))

	// Map chart in index.html will call /data.json to read data
	http.HandleFunc("/data.json", mapDataHandler)

	log.Println("Listening on :80...")
	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Fatal(err)
	}

}

// readRequests reads requests from channel
// request must be a string containing the ipv4 address
// example: 8.8.8.8
func readRequests() {
	for {
		select {
		case ip := <-requests:
			fmt.Println("New request from: ", ip)
			go processRequest(ip)
		}
	}

}

// processRequest invokes geoIP database to get country code
// then increments 2 counters:
// - specific counter for country code
// - global counter
func processRequest(ip string) {
	countryCode := getCountryByIP(ip)
	requestsByCountry[countryCode]++
	requestsTotal++
}

// getCountryByIP given a IPv4 address it returns
// a country code (I.E. "ES")
func getCountryByIP(ip string) string {
	country, _ := gi.GetCountry(ip)
	return country

}

// mapDataHandler writes the json body needed to draw in the map (index.html)
// The returned object needs to be an array of:
// name: Name of the country
// id: country ID
// percent: percent of the total requests in that country
// amount: number requests in that country
func mapDataHandler(w http.ResponseWriter, req *http.Request) {
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
