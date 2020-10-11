# eBPF geoip demo
This repository contains the resources to be used during the eBPF Summit demo.

## Demo overview
**The high level idea for the demo:**<br/>
Having x services running in a server exposed in different ports, without having to edit or make any changes at all to them, it is possible to monitor from which locations of the world are those being consumed.<br/>
The attendees could try making http GET request to any of the services, and in real time we will be able to see in the map the points from where the Summit attendees are joining.<br/>


<img src="/docs/demoOverview.png" alt="demoOverviewDiagram">

<br/>

**Events flow:**
* The server to be used will be a Ubuntu VM from GCP (or other cloud provider).
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

## Environment setup
For GeoIP to work you need to have GeoIP lib installed in the system, as the used Go lib is just a wrapper.
You first need to install geoip lib in your system:

MacOS:
```
brew install geoip
```

Ubuntu
```
apt-get install -y geoip-database
```

## Run

To run:

```
go run main.go
```

And access http://localhost:3000 to check the map

### Create word with POST
```
curl -X POST http://localhost:3000/word -d 'word'
```

### Create a sample request with an IP

US IP Address
```
curl -X POST http://localhost:3000/request -d '8.8.8.8'
```

ES IP Address
```
curl -X POST http://localhost:3000/request -d '138.100.31.225'
