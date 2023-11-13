// Copyright 2023 Brian Swetland <swetland@frotz.net>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package infodump

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
)

func ValidHexName(hexname string) bool {
	if len(hexname) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := hexname[i]
		if (c >= '0') && (c <= '9') {
			continue
		}
		if (c >= 'a') && (c <= 'f') {
			continue
		}
		return false
	}
	return true
}

type BlobStore interface {
	Put([]byte) (string, error)
	PutStream(io.Reader) (string, error)
	Get(hexname string) ([]byte, error)
	Open(hexname string) (io.ReadCloser, error)
	GetSize(hexname string) (int64, error)
}

type blobInfo struct {
	size int64
}

type blobStore struct {
	path string
	info map[string]blobInfo
	lock sync.Mutex
}

type BlobStorePreloader interface {
	PreloadBlob(string, []byte) error
}

const maxObjectSize = 64 * 1024

func NewBlobStore(_path string, preloader BlobStorePreloader) BlobStore {
	if !strings.HasSuffix(_path, "/") {
		_path = _path + "/"
	}
	bs := &blobStore{
		path: _path,
		info: make(map[string]blobInfo),
	}

	f, err := os.Open(_path)
	if err != nil {
		return bs
	}
	for {
		list, err := f.Readdir(128)
		if err != nil {
			break
		}
		for _, info := range list {
			if (info.Mode() & fs.ModeType) != 0 {
				// not a regular file
				continue
			}
			name := info.Name()
			if len(name) != 64 {
				// not a valid sha256 filename
				continue
			}
			// TODO: optionally verify filename is hex & matches
			// TODO: strategies for small/med/large files
			// (eg, for med, read and check magic first)
			if (preloader != nil) && (info.Size() < maxObjectSize) {
				data, err := os.ReadFile(bs.path + name)
				if err != nil {
					continue
				}
				if preloader.PreloadBlob(name, data) != nil {
					continue
				}
			}
			bs.info[name] = blobInfo{size: info.Size()}
		}
	}
	_ = f.Close()
	return bs
}

func (bs *blobStore) Put(data []byte) (string, error) {
	hash := sha256.New()
	hash.Write(data)
	hexname := hex.EncodeToString(hash.Sum(nil))

	file, err := os.CreateTemp(bs.path, ".tmp.")
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		os.Remove(file.Name())
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(file.Name())
		return "", err
	}
	if os.Rename(file.Name(), bs.path+"/"+hexname) != nil {
		os.Remove(file.Name())
		return "", err
	}

	bs.lock.Lock()
	bs.info[hexname] = blobInfo{size: int64(len(data))}
	bs.lock.Unlock()
	return hexname, nil
}

func (bs *blobStore) PutStream(_r io.Reader) (hexname string, err error) {
	hash := sha256.New()
	r := io.TeeReader(_r, hash)

	var count int64
	var file *os.File

	file, err = os.CreateTemp(bs.path, ".tmp.")
	if err != nil {
		return
	}
	if count, err = io.Copy(file, r); err != nil {
		os.Remove(file.Name())
		_ = file.Close()
		return
	}
	if err = file.Close(); err != nil {
		os.Remove(file.Name())
		return
	}

	hexname = hex.EncodeToString(hash.Sum(nil))
	if os.Rename(file.Name(), bs.path+"/"+hexname) != nil {
		os.Remove(file.Name())
		return "", err
	}

	bs.lock.Lock()
	bs.info[hexname] = blobInfo{size: count}
	bs.lock.Unlock()
	return
}

func (bs *blobStore) Open(hexname string) (io.ReadCloser, error) {
	if !ValidHexName(hexname) {
		return nil, ErrBadName
	}
	file, err := os.Open(bs.path + "/" + hexname)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (bs *blobStore) Get(hexname string) ([]byte, error) {
	if !ValidHexName(hexname) {
		return nil, ErrBadName
	}
	bs.lock.Lock()
	_, ok := bs.info[hexname]
	bs.lock.Unlock()
	if !ok {
		return nil, ErrNotFound
	}

	data, err := os.ReadFile(bs.path + "/" + hexname)
	if err != nil {
		return nil, err
	}
	//TODO verify sha256 option?
	return data, nil
}

func (bs *blobStore) GetSize(hexname string) (int64, error) {
	bs.lock.Lock()
	info, ok := bs.info[hexname]
	bs.lock.Unlock()
	if ok {
		return info.size, nil
	} else {
		return 0, ErrNotFound
	}
}

type memoryBlobInfo struct {
	data []byte
}

type memoryBlobStore struct {
	path string
	blob map[string]memoryBlobInfo
	lock sync.Mutex
}

func NewMemoryBlobStore() BlobStore {
	return &memoryBlobStore{
		blob: make(map[string]memoryBlobInfo),
	}
}

func (bs *memoryBlobStore) Put(data []byte) (hexname string, err error) {
	hash := sha256.New()
	hash.Write(data)
	hexname = hex.EncodeToString(hash.Sum(nil))
	bs.lock.Lock()
	bs.blob[hexname] = memoryBlobInfo{data}
	bs.lock.Unlock()
	return
}

func (bs *memoryBlobStore) PutStream(r io.Reader) (hexname string, err error) {
	if data, err := io.ReadAll(r); err == nil {
		hexname, err = bs.Put(data)
	}
	return
}

func (bs *memoryBlobStore) GetSize(hexname string) (int64, error) {
	bs.lock.Lock()
	blob, ok := bs.blob[hexname]
	bs.lock.Unlock()
	if ok {
		return int64(len(blob.data)), nil
	} else {
		return 0, ErrNotFound
	}
}

func (bs *memoryBlobStore) Get(hexname string) ([]byte, error) {
	bs.lock.Lock()
	blob, ok := bs.blob[hexname]
	bs.lock.Unlock()
	if ok {
		return blob.data, nil
	} else {
		return nil, ErrNotFound
	}
}

type closeableReader struct {
	r io.Reader
}

func (cr *closeableReader) Read(data []byte) (int, error) {
	return cr.r.Read(data)
}

func (cr *closeableReader) Close() error {
	return nil
}

func (bs *memoryBlobStore) Open(hexname string) (io.ReadCloser, error) {
	data, err := bs.Get(hexname)
	if err != nil {
		return nil, err
	} else {
		return &closeableReader{bytes.NewReader(data)}, nil
	}
}
