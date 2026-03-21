package main

import "crypto/rand"

func cryptoRead(p []byte) (int, error) {
	return rand.Read(p)
}
