# Tracing Go function with eBPF
We are going to be using the simple Go server [app-3](https://github.com/b3a-dev/ebpf-geoip-demo/tree/master/app-x/app-3) that will be accepting http requests:
```
GET http://pubIP:8083/`my_word` -> "Submitted word: `my_word`"
```
* When you go build it, the function that receives the posted word as parameter is created as a symbol in the created binary.
* Uprobes let you create a hook at a memory address anywhere in userspace.
* You can attach a uprobe to the function symbol, which you can have trigger an eBPF program. 
* The uprobe is copied into memory anytime the binary is executed, meaning it will trigger anytime any process runs that function. 
* Then using the gobpf library, we can write a small eBPF program that will be triggered anytime the function in the simple Go server is executed, with every post with a word.
* By using an eBPF map, we can then read the words written by the ebpf side, and build a words-cloud that will be served and exposed with a public IP.


## Demo Steps
### Setup the server
* The server used is an Ubuntu VM from GCP (or other cloud provider).
* Don't forget to allow http traffic for this instance.
* Install dependencies: bcc from sources: https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source

*Note: the listed steps didn't word for me and in order to fix an error I had to add this step:
```
sudo apt-get install python3-distutils --reinstall
```

### Run the simple Go server
We need the binary of the server [app-3](https://github.com/b3a-dev/ebpf-geoip-demo/tree/master/app-x/app-3) as we will use it as parameter.

```
cd app-3
go build
./<binaryName>
```

### Run tracing
Right now this app is taking the name of the binary that contains the function we are going to be tracing as parameter.

```
go run main.go /path/to/app-3/binary/<binaryName>
```




