# eBPF geoip demo
This repository contains the resources to be used during the eBPF Summit demo.
* **app-x**: contains 1 directory per independent app that would be running in the server.
* **bpf**: contains ebpf program that inspect incoming TCP packets with the configured destination port, get source IP addresses and write those in a eBPF map, used by the go userspace application.
* **static**: static files to show a map in the browser with the representation of the places in the world form where different app-x are accessed.
* **docs**: documentation screenshots.
* **root dir**: contains a simple userspace Go server that reads from the eBPF map and shows those updating the map that is serving.
* **tracing**: contains an independent second part of the demo, consist on tracing a Go function with eBPF.

## Demo overview
**The high level idea for the demo:**<br/>
Having x services running in a server exposed in different ports, without having to edit or make any changes at all to them, it is possible to monitor from which locations of the world are those being consumed.<br/>
The attendees could try making http GET request to any of the services, and in real time we will be able to see in the map the points from where the Summit attendees are joining.<br/>


<img src="/docs/demoOverview.png" alt="demoOverviewDiagram">

<br/>

**Events flow:**
* The server used is an Ubuntu VM from GCP (or other cloud provider).
* There would be services running in the VM, exposed using different ports, in the diagram: 8081, 8082 and 8083.
* A eBPF program will gather the source IPs from the requests and share those with userspace Go app by using an eBPF map.
* The Go app will get the location with a geoip service.
* Depending on the number of requests from the same country a json structure will be formed.
* Reading from the json structure the map will represent points with different sized in those countries with attendees.
* Additionally more info could be gathered such: number of requests from same IP, number of different IPs (should be the same of number of attendees to the session), which services are accessing..


## Demo Steps
### Setup the server
* The server used is an Ubuntu VM from GCP (or other cloud provider).
* Don't forget to allow http traffic for this instance.
* TODO: Configure fw rules to permit traffic to ports: 8081, 8082 and 8083.
* Install dependencies

```
$ sudo apt update
$ sudo apt install make llvm clang golang-go
$ git clone git@github.com:cilium/cilium.git
```

For GeoIP to work you need to have GeoIP lib installed in the system, as the used Go lib is just a wrapper.
```
$ sudo apt-get install -y geoip-database
$ libgeoip-dev
```

### Deploy the independent applications
* `app-x`: contains 1 directory per independent app that would be running in the server.
    - app-1: running in port 8081, GET http://pubIP:8081/ -> "Hello World!"
    - app-2: running in port 8082, GET http://pubIP:8082/ -> "eBPF Summit"
    - app-3: running in port 8083, GET http://pubIP:8083/`my_word` -> "Submitted word: `my_word`"


* Run the servers by running in each app-x directory:
```
$ go run main.go&
```
<img src="/docs/app-xRunning.png" alt="app-xRunning" width="400">

* You can test the above behavior by using both curl or a browser.

<img src="/docs/app3-submitWord.png" alt="app3-submitWord" width="400">


### Compile and install the eBPF program
Inspects incoming TCP packets with the configured destination port (initially 80), get source IP addresses and write those in a eBPF map, used by the go userspace application.

#### Compile:
```
$ CILIUM_DIR=~/cilium/ make -C bpf/
```

#### Attach the eBPF program:
This is a tc (traffic control) subsystem program. The [tc(8)](http://man7.org/linux/man-pages/man8/tc-bpf.8.html) command has eBPF support, so we can directly load BPF programs as classifiers. tc programs can classify, modify, redirect or drop packets.
The basics are: create a "clsact" qdisc classifier for a network device `ens4`, and then add an ingress classifier/filter by specifying the BPF object and relevant ELF section. Example, to add an ingress classifier to ens4 in ELF section `bpf-prog` from tc-prog.o (a bpf-bytecode-compiled object file):

```
$ sudo tc qdisc add dev ens4 clsact
$ sudo tc filter add dev ens4 ingress bpf da obj bpf/tc-prog.o sec bpf-prog
$ sudo tc filter show dev ens4 ingress
```

Expected output from last previous command:
```
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-prog.o:[bpf-prog] direct-action not_in_hw id 77 tag 1e2a2ca8a73223a5 jited
```

In the case of ingress, we do classification via the core network interface receive function, so we are getting the packet after the driver has processed it but before IP etc 


To cleanup:
```
$ sudo sudo tc filter delete dev ens4 ingress pref 49152 handle 0x1 bpf 
$ sudo rm /sys/fs/bpf/tc/globals/xevents
```

### Run the userpace Go server
Simple userspace Go server that reads from the eBPF map the source IP addresses written by the eBPF program and shows those updating the map that is serving.

```
$ sudo go run main.go
```

And access http://pubIP to check the map:

<img src="/docs/requestsByCountry.png" alt="requestsByCountry">

