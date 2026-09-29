//go:build linux

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func runtimeFDIsTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	var terminal syscall.Termios
	return runtimeIoctl(file.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&terminal))) == nil
}

func runtimeReadHiddenLine(file *os.File, maximum int) ([]byte, error) {
	if file == nil {
		return nil, errRuntimeInput
	}
	var original syscall.Termios
	if err := runtimeIoctl(file.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&original))); err != nil {
		return nil, errRuntimeInput
	}
	hidden := original
	hidden.Lflag &^= syscall.ECHO | syscall.ECHONL
	if err := runtimeIoctl(file.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&hidden))); err != nil {
		return nil, errRuntimeInput
	}
	restored := false
	defer func() {
		if !restored {
			_ = runtimeIoctl(file.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&original)))
		}
	}()
	value, readErr := readBoundedRuntimeLine(file, maximum)
	restoreErr := runtimeIoctl(file.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&original)))
	restored = restoreErr == nil
	if readErr != nil || restoreErr != nil {
		clearRuntimeBytes(value)
		return nil, errRuntimeInput
	}
	return value, nil
}

func runtimeIoctl(fd uintptr, request uintptr, argument uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, request, argument, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func readRootOwnedRuntimePublicFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, errRuntimeConfiguration
	}
	clean, err := cleanAbsoluteRuntimePath(path, true)
	if err != nil {
		return nil, err
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errRuntimeConfiguration
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return nil, errRuntimeConfiguration
		}
		if index == len(parts)-1 {
			if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
				return nil, errRuntimeConfiguration
			}
		} else if !info.IsDir() {
			return nil, errRuntimeConfiguration
		}
	}
	fd, err := syscall.Open(clean, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errRuntimeConfiguration
	}
	file := os.NewFile(uintptr(fd), clean)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errRuntimeConfiguration
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > maximum {
		return nil, errRuntimeConfiguration
	}
	after, err := os.Lstat(clean)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) {
		return nil, errRuntimeConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		clearRuntimeBytes(data)
		return nil, fmt.Errorf("%w: bounded public trust file", errRuntimeConfiguration)
	}
	return data, nil
}
