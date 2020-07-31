package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

func (cl *CryptLog) SetBlock(salt []byte) error {
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

func New(key string) (*CryptLog, error) {
	return &CryptLog{
		key: []byte(key),
	}, nil
}

func indexPadding(block []byte) int {
	var lastZero int
	for x := len(block) - 1; x >= 0; x-- {
		if block[x] == 0 {
			lastZero = x
		}
	}
	return lastZero
}

func calculatePadding(length int) int {
	if p := length % aes.BlockSize; p != 0 {
		return aes.BlockSize - p
	}
	return 0
}

func (cl *CryptLog) buildOutput(lastTwo, data []byte) (iv, out []byte, err error) {
	if len(lastTwo) != 2*aes.BlockSize {
		return nil, nil, ErrLastTwoSize
	}
	iv = lastTwo[:aes.BlockSize]
	decrypter := cipher.NewCBCDecrypter(cl.block, iv)
	decrypter.CryptBlocks(lastTwo[aes.BlockSize:], lastTwo[aes.BlockSize:])
	pIdx := indexPadding(lastTwo[aes.BlockSize:])
	length := len(data) + len(lastTwo[:pIdx])
	padding := calculatePadding(length)
	out = make([]byte, length+padding)
	copy(out[:aes.BlockSize], lastTwo[aes.BlockSize:])
	copy(out[pIdx:], data)
	return iv, out, nil
}

func Init(log io.Writer) ([]byte, error) {
	header := make([]byte, 2*aes.BlockSize)
	_, err := rand.Reader.Read(header[:aes.BlockSize])
	if err != nil {
		return nil, err
	}
	_, err = log.Write(header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func (cl *CryptLog) Append(log CryptLogAppender, data []byte) error {
	if data == nil {
		return nil
	}
	lastTwo, err := log.LastTwoBlocks()
	if err != nil {
		return err
	}
	if lastTwo == nil {
		lastTwo, err = Init(log)
		if err != nil {
			return err
		}
	}
	salt, err := log.GetSalt()
	if err != nil {
		return err
	}
	if err = cl.SetBlock(salt); err != nil {
		return err
	}
	iv, out, err := cl.buildOutput(lastTwo, data)
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
