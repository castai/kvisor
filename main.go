package main

import (
	"fmt"
	"time"
)

func main() {
	for range time.Tick(time.Second) {
		// https://en.wikipedia.org/wiki/Heart_sounds
		fmt.Println("lub dub")
	}
}
