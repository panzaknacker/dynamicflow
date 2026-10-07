package cli

import (
	"errors"
	"io"
	"os"
)

type streamInstanceRuntimeInput struct {
	reader    io.Reader
	finalized bool
}

type ttyInstanceRuntimeInput struct {
	file      *os.File
	writer    io.Writer
	closeFile bool
}

func openDefaultInstanceRuntimeInput(stdin io.Reader) (instanceRuntimeInput, error) {
	if stdin == nil {
		return nil, errRuntimeInput
	}
	if file, ok := stdin.(*os.File); ok && runtimeFDIsTerminal(file) {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err == nil {
			return &ttyInstanceRuntimeInput{file: tty, writer: tty, closeFile: true}, nil
		}
		// A controlling terminal can be absent in a constrained console even
		// though stdin itself is a TTY. Duplicate the terminal through procfs
		// so prompts never pollute structured stdout/stderr and Close remains
		// safe for process stdin.
		duplicate, duplicateErr := os.OpenFile("/proc/self/fd/0", os.O_RDWR, 0)
		if duplicateErr != nil {
			return nil, errRuntimeInput
		}
		return &ttyInstanceRuntimeInput{file: duplicate, writer: duplicate, closeFile: true}, nil
	}
	return &streamInstanceRuntimeInput{reader: stdin}, nil
}

func (input *streamInstanceRuntimeInput) ReadField(_ string, _ bool, maximum int) ([]byte, error) {
	return readBoundedRuntimeLine(input.reader, maximum)
}

func (input *streamInstanceRuntimeInput) Finalize() error {
	input.finalized = true
	var one [1]byte
	for attempts := 0; attempts < 32; attempts++ {
		count, err := input.reader.Read(one[:])
		if count != 0 {
			return errRuntimeInput
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errRuntimeInput
		}
	}
	return errRuntimeInput
}

func (input *streamInstanceRuntimeInput) Close() error { return nil }

func (input *ttyInstanceRuntimeInput) ReadField(prompt string, hidden bool, maximum int) ([]byte, error) {
	if _, err := io.WriteString(input.writer, prompt); err != nil {
		return nil, errRuntimeInput
	}
	if !hidden {
		return readBoundedRuntimeLine(input.file, maximum)
	}
	value, err := runtimeReadHiddenLine(input.file, maximum)
	_, newlineErr := io.WriteString(input.writer, "\n")
	if err != nil || newlineErr != nil {
		clearRuntimeBytes(value)
		return nil, errRuntimeInput
	}
	return value, nil
}

func (input *ttyInstanceRuntimeInput) Finalize() error { return nil }

func (input *ttyInstanceRuntimeInput) Close() error {
	if input.closeFile {
		return input.file.Close()
	}
	return nil
}

func readBoundedRuntimeLine(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum <= 0 || maximum > 4096 {
		return nil, errRuntimeInput
	}
	value := make([]byte, 0, maximum)
	tooLong := false
	sawInput := false
	var one [1]byte
	for emptyReads := 0; ; {
		count, err := reader.Read(one[:])
		if count > 0 {
			emptyReads = 0
			sawInput = true
			if one[0] == '\n' {
				break
			}
			if len(value) < maximum+1 {
				value = append(value, one[0])
			} else {
				tooLong = true
			}
		} else {
			emptyReads++
		}
		if err != nil {
			if errors.Is(err, io.EOF) && sawInput {
				break
			}
			clearRuntimeBytes(value)
			return nil, errRuntimeInput
		}
		if emptyReads > 32 {
			clearRuntimeBytes(value)
			return nil, errRuntimeInput
		}
	}
	if len(value) > 0 && value[len(value)-1] == '\r' {
		value = value[:len(value)-1]
	}
	if tooLong || len(value) == 0 || len(value) > maximum {
		clearRuntimeBytes(value)
		return nil, errRuntimeInput
	}
	return value, nil
}
