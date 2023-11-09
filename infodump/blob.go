// Copyright 2023 Brian Swetland <swetland@frotz.net>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package infodump

import (
	"crypto/sha256"
	"encoding/hex"
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

type BlobInfo struct {
	size int64
}

type BlobStore struct {
	path string
	info map[string]BlobInfo
	lock sync.Mutex
}

type BlobStorePreloader interface {
	PreloadBlob(string, []byte) error
}

func NewBlobStore(_path string, preloader BlobStorePreloader) *BlobStore {
	if !strings.HasSuffix(_path, "/") {
		_path = _path + "/"
	}
	bs := &BlobStore{
		path: _path,
		info: make(map[string]BlobInfo),
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
			if preloader != nil {
				data, err := os.ReadFile(bs.path + name)
				if err != nil {
					continue
				}
				if preloader.PreloadBlob(name, data) != nil {
					continue
				}
			}
			bs.info[name] = BlobInfo{size: info.Size()}
		}
	}
	_ = f.Close()
	return bs
}

func (bs *BlobStore) Put(data []byte) (string, error) {
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
		return "", err
	}
	if os.Rename(file.Name(), bs.path+"/"+hexname) != nil {
		os.Remove(file.Name())
		return "", err
	}

	bs.lock.Lock()
	bs.info[hexname] = BlobInfo{size: int64(len(data))}
	bs.lock.Unlock()
	return hexname, nil
}

//TODO use openat()

func (bs *BlobStore) Open(hexname string) (*os.File, error) {
	if !ValidHexName(hexname) {
		return nil, ErrBadName
	}
	file, err := os.Open(bs.path + "/" + hexname)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (bs *BlobStore) Get(hexname string) ([]byte, error) {
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

func (bs *BlobStore) GetSize(hexname string) (int64, error) {
	bs.lock.Lock()
	info, ok := bs.info[hexname]
	bs.lock.Unlock()
	if ok {
		return info.size, nil
	} else {
		return -1, ErrNotFound
	}
}
