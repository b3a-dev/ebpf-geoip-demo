package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", helloServer)
	http.ListenAndServe(":8083", nil)
}

func helloServer(w http.ResponseWriter, r *http.Request) {
	respond(w, r.URL.Path[1:])
}

func respond(w http.ResponseWriter, word string) {
	fmt.Fprintf(w, "Submitted word: %s!\n", word)
}
