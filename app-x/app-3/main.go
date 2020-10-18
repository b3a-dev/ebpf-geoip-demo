package main

import (
	"fmt"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", helloServer)
	http.ListenAndServe(":8083", nil)
}

func helloServer(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Submitted word: %s!\n", r.URL.Path[1:])
	word := strings.TrimSpace(r.URL.Path[1:])
	postWord(word)
}

func postWord(word string) {
	fmt.Println("New request with word:", word)
}
