//go:build windows
// +build windows
package main

import "syscall"

func Setfile(localfile string) {
    p, err := syscall.UTF16PtrFromString(localfile)
	if err == nil {
	attr, err := syscall.GetFileAttributes(p)
	if err == nil {
	syscall.SetFileAttributes(p, attr|syscall.FILE_ATTRIBUTE_HIDDEN)
		}}
	return
}