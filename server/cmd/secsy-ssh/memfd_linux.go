package main

import "golang.org/x/sys/unix"

func memfdCreate(name string) (uintptr, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return 0, err
	}
	return uintptr(fd), nil
}
