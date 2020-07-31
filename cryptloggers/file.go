package cryptloggers

import (
	"crypto/aes"
	"errors"
	"fmt"
	"os"
)

type FileCryptLogger struct {
	file    *os.File
	writeAt int64
}

func OpenFile(name string) (*FileCryptLogger, error) {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size%aes.BlockSize != 0 {
		return nil, errors.New("invalid size")
	}
	// writeAt should be one AES block behind the end of the file,
	// except for new files
	var writeAt int64
	if size == 0 {
		writeAt = 0
	} else {
		writeAt = size - aes.BlockSize
	}
	return &FileCryptLogger{
		file:    file,
		writeAt: writeAt,
	}, nil
}

func (fcl *FileCryptLogger) LastTwoBlocks() ([]byte, error) {
	if fcl.writeAt == 0 {
		return nil, nil
	}
	out := make([]byte, 2*aes.BlockSize)
	_, err := fcl.file.ReadAt(out, fcl.writeAt-aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("unable to read last two blocks: %w", err)
	}
	// Reset reader after fetching last two blocks
	if _, err = fcl.file.Seek(0, 0); err != nil {
		return nil, err
	}
	return out, nil
}

func (fcl *FileCryptLogger) GetSalt() ([]byte, error) {
	if fcl.writeAt == 0 {
		return nil, errors.New("file is unwritten")
	}
	salt := make([]byte, aes.BlockSize)
	_, err := fcl.file.ReadAt(salt, 0)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (fcl *FileCryptLogger) Read(b []byte) (int, error) {
	return fcl.file.Read(b)
}

func (fcl *FileCryptLogger) Write(b []byte) (int, error) {
	written, err := fcl.file.WriteAt(b, fcl.writeAt)
	fcl.writeAt += int64(written) - aes.BlockSize
	return written, err
}

func (fcl *FileCryptLogger) WriteAt(b []byte, off int64) (int, error) {
	return fcl.file.WriteAt(b, off)
}

func (fcl *FileCryptLogger) Close() error {
	return fcl.file.Close()
}
