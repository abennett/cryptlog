package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/scrypt"
)

var (
	ErrLastTwoSize = errors.New("last two blocks are not the correct size")
)

type CryptLog struct {
	key   []byte
	block cipher.Block
}

// New creates a CryptLog and saves the provided key. Setting the
// actual cipher.Block comes later and depends on salt stored in
// the CryptLogAppender
func New(key string) (*CryptLog, error) {
	return &CryptLog{
		key: []byte(key),
	}, nil
}

func (cl *CryptLog) SetBlock(salt []byte) error {
	// the following is based on recommendations in the docs
	// https://godoc.org/golang.org/x/crypto/scrypt#Key
	k, err := scrypt.Key(cl.key, salt, 32768, 8, 1, 32)
	if err != nil {
		return err
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil
	}
	cl.block = b
	return nil
}

type CryptLogAppender interface {
	LastTwoBlocks() ([]byte, error)
	GetSalt() ([]byte, error)
	io.ReadWriteCloser
	io.WriterAt
}

// indexPadding locates where the zero padding begins
func indexPadding(block []byte) int {
	var lastZero int
	for x := len(block) - 1; x >= 0; x-- {
		if block[x] == 0 {
			lastZero = x
		}
	}
	return lastZero
}

// calculatePadding calculates how much padding is needed
// to fit into aes-appropriate blocks
func calculatePadding(length int) int {
	if p := length % aes.BlockSize; p != 0 {
		return aes.BlockSize - p
	}
	return 0
}

func printBlocks(b []byte) {
	var last, count int
	for x := 16; x <= len(b); x += 16 {
		count++
		fmt.Printf("%d: %v\t%s\n", count, b[last:x], b[last:x])
	}
}

// decryptLast decrypts the last block of the last two blocks returned
// by the CryptLogAppender as it has to be decrypted to be rewrote
func (cl *CryptLog) decryptLast(lastTwo []byte) error {
	if len(lastTwo) != 2*aes.BlockSize {
		return ErrLastTwoSize
	}
	iv := lastTwo[:aes.BlockSize]
	decrypter := cipher.NewCBCDecrypter(cl.block, iv)
	decrypter.CryptBlocks(lastTwo[aes.BlockSize:], lastTwo[aes.BlockSize:])
	return nil
}

// buildOutput takes a decrypted lastTwo and the data to be input and builds the
// actual slice that will be appended to the CryptLogAppender
func (cl *CryptLog) buildOutput(lastTwoDecrypted, data []byte) (out []byte, err error) {
	if len(lastTwoDecrypted) != 2*aes.BlockSize {
		return nil, ErrLastTwoSize
	}
	pIdx := indexPadding(lastTwoDecrypted[aes.BlockSize:])
	length := len(data) + len(lastTwoDecrypted[:pIdx])
	padding := calculatePadding(length)
	out = make([]byte, length+padding)
	// the last block of lastTwo is the first to be written
	copy(out[:aes.BlockSize], lastTwoDecrypted[aes.BlockSize:])
	// zero padding of the last block of lastTwo is written into based on
	// the padding index
	copy(out[pIdx:], data)
	return out, nil
}

// Init initialized a new io.Writer by writing the salt/starting iv
// and sets the cipher.Block of CryptLog with it
func (cl *CryptLog) Init(log io.Writer) ([]byte, error) {
	header := make([]byte, 2*aes.BlockSize)
	// read just the first block and leave the last block as zeroes
	_, err := rand.Reader.Read(header[:aes.BlockSize])
	if err != nil {
		return nil, err
	}
	_, err = log.Write(header)
	if err != nil {
		return nil, err
	}
	err = cl.SetBlock(header[:aes.BlockSize])
	return header, err
}

func (cl *CryptLog) Append(log CryptLogAppender, data []byte) error {
	// Quick return if nothing to append
	if data == nil {
		return nil
	}
	lastTwo, err := log.LastTwoBlocks()
	if err != nil {
		return err
	}
	// Assumes if lastTwo is nil, it's a new CryptLogAppender
	if lastTwo == nil {
		lastTwo, err = cl.Init(log)
		if err != nil {
			return err
		}
	} else {
		// Getting the salt and setting the CryptLog block is reqired
		// before actually decrypting any bytes
		salt, err := log.GetSalt()
		if err != nil {
			return err
		}
		if err = cl.SetBlock(salt); err != nil {
			return err
		}
		err = cl.decryptLast(lastTwo)
		if err != nil {
			return err
		}
	}
	// the first block of the lastTwo will remain encrypted and
	// servce as the iv for the following block
	iv := lastTwo[:aes.BlockSize]
	out, err := cl.buildOutput(lastTwo, data)
	if err != nil {
		return err
	}
	encrypter := cipher.NewCBCEncrypter(cl.block, iv)
	cipher := make([]byte, len(out))
	encrypter.CryptBlocks(cipher, out)
	_, err = log.Write(cipher)
	return err
}

func (cl *CryptLog) Decrypt(log CryptLogAppender) ([]byte, error) {
	cipherText, err := ioutil.ReadAll(log)
	if err != nil {
		return nil, err
	}
	salt, err := log.GetSalt()
	if err != nil {
		return nil, err
	}
	if err = cl.SetBlock(salt); err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(cl.block, cipherText[:aes.BlockSize])
	decrypter.CryptBlocks(cipherText[aes.BlockSize:], cipherText[aes.BlockSize:])
	return cipherText[aes.BlockSize:], nil
}
