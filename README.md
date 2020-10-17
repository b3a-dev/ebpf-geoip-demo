# eBPF geoip demo
This repository contains the resources to be used during the eBPF Summit demo.
* app-x: contains 1 directory per independent app that would be running in the server.
* bpg: contains ebpf program that inspect incoming TCP packets with the configured destination port, get source IP addresses and write those in a eBPF map, used by the go userspace application.
* static: static files to show a map in the browser with the representation of the places in the world form where different app-x are accessed.
* docs: documentation screenshots.
* The root contains a simple userspace Go server that reads from the eBPF map and shows those updating the map that is serving.

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
* Reading from the json structure the map will represent in real-time points with different sized in those countries with attendees.
* Additionally more info could be gathered such: number of requests from same IP, number of different IPs (should be the same of number of attendees to the session), which services are accessing..

## Current implementation status
The eBPF side is not yet done, in order to simulate the behavior:
* There is an additional endpoint `request` that allows to send IP addresses.
* Those IP addresses are handled by the function `exampleRequest`, and send to a go channel `requests`.

The Go app then:
* Reads those IPs from the go channel and process them. 
* Once the eBPF side is setup, instead of reading those IP addresses from the Go channel they will be read from the eBPF map and process them the same way.

**Potential additions:**
* Make real-time updates in the client side so there is no need to reload the page to see the new data points in the map.
* Additional endpoint prepared in case there is enough time to implement the post of words and visualization as Words Cloud together with the map.


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
<img src="/docs/app-xRunning.png" alt="app-xRunning">

* You can test the above behavior by using both curl or a browser.
<img src="/docs/app3-submitWord.png" alt="app3-submitWord">


### Compile and install the eBPF program
Inspects incoming TCP packets with the configured destination port (initially 80), get source IP addresses and write those in a eBPF map, used by the go userspace application.
```
$ CILIUM_DIR=~/cilium/ make -C bpf/
$ sudo tc qdisc add dev ens4 clsact
$ sudo tc filter add dev ens4 ingress bpf da obj bpf/tc-prog.o sec bpf-prog
$ sudo tc filter show dev ens4 ingress
```

Expected output from last previous command:
```
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 tc-prog.o:[bpf-prog] direct-action not_in_hw id 77 tag 1e2a2ca8a73223a5 jited
```

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

