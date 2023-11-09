// Copyright 2023 Brian Swetland <swetland@frotz.net>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package infodump

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"regexp"
)

var validPathRe = regexp.MustCompile(`^[a-z0-9_:-]+(/[a-z0-9_:-]+)*$`)

func IsValidPath(path string) bool {
	return validPathRe.MatchString(path)
}

type Object struct {
	Type      string            // mime type
	Path      string            // human-friendly name
	BlobRef   string            // hash of our content
	ParentRef string            // hash of our previous version
	CTime     int64             // creation time UnixNanos
	MTime     int64             // modification time UnixNanos
	Tags      []string          // associated tags
	Attr      map[string]string // content metadata nv pairs

	RefCount int32  // number of parents
	SelfRef  string // hash of our serialized form
	Parent   *Object
}

type ObjectJson struct {
	Type      string
	Path      string
	BlobRef   string
	ParentRef string
	CTime     string
	MTime     string
	Tags      []string
	Attr      map[string]string
	InfoHash  string
}

// magic values
var infodump = []byte("{\"infodump\":1,")
var infohash = []byte(",\"infohash\":\"")

// magic values without the leading/trailing commas
var infodumpNoComma = infodump[:len(infodump)-1]
var infohashNoComma = infohash[2:]

func NewObject(b []byte) (o *Object, err error) {
	var t ObjectJson

	// require magic/version
	if !bytes.HasPrefix(b, infodump) {
		return nil, ErrBadMagic
	}

	// require valid JSON
	if err = json.Unmarshal(b, &t); err != nil {
		return
	}

	// determine end of payload (before the hash kv)
	n := bytes.LastIndex(b, infohash)
	if n < 0 {
		return nil, ErrBadHash
	}

	// TODO: avoid allocating sha256
	// TODO: avoid hash->string for comparison
	hash := sha256.New()
	hash.Write(b[:n])
	if t.InfoHash != hex.EncodeToString(hash.Sum(nil)) {
		return nil, ErrBadHash
	}

	if (t.Path != "") && !validPathRe.MatchString(t.Path) {
		return nil, ErrBadName
	}

	// TODO: pass in as an argument?
	hash = sha256.New()
	hash.Write(b)
	sum := hash.Sum(nil)

	// 0 on parse error
	ctime, _ := strconv.ParseInt(t.CTime, 10, 64)
	mtime, _ := strconv.ParseInt(t.MTime, 10, 64)

	o = &Object{
		Type:      t.Type,
		Path:      t.Path,
		BlobRef:   t.BlobRef,
		ParentRef: t.ParentRef,
		CTime:     ctime,
		MTime:     mtime,
		Tags:      t.Tags,
		Attr:      t.Attr,
		SelfRef:   string(sum),
	}
	return
}

func (o *Object) Serialize() []byte {
	// string maps get marshalled into json in key sort order
	payload := make(map[string]interface{})
	payload["type"] = o.Type
	payload["path"] = o.Path
	payload["blobref"] = o.BlobRef
	payload["parentref"] = o.ParentRef
	payload["ctime"] = strconv.FormatInt(o.CTime, 10)
	payload["mtime"] = strconv.FormatInt(o.MTime, 10)
	if o.Tags != nil {
		payload["tags"] = o.Tags
	}
	if o.Attr != nil {
		payload["attr"] = o.Attr
	}

	buf := new(bytes.Buffer)

	// prepend magic/version kv
	buf.Write(infodumpNoComma)

	enc := json.NewEncoder(buf)
	hexenc := hex.NewEncoder(buf)
	enc.Encode(payload)

	// replace leading '{' of json with ,
	// to glue the infodump kv to the front
	b := buf.Bytes()
	b[len(infodumpNoComma)] = ','

	// replace the closing '}' and newline
	// with the infohash kv
	b = buf.Bytes()
	n := len(b)
	b[n-2] = ','
	b[n-1] = '"'
	buf.Write(infohashNoComma)

	// compute the sha256 of the json preceeding
	// the trailing ,"infohash":
	hash := sha256.New()
	hash.Write(b[:n-2])
	hexenc.Write(hash.Sum(nil))
	buf.WriteString("\"}\n")

	return buf.Bytes()
}

func (o *Object) SetAttr(name string, value string) {
	if o.Attr == nil {
		o.Attr = map[string]string{
			name: value,
		}
	} else {
		o.Attr[name] = value
	}
}

type ObjectStore struct {
	bs      *BlobStore
	refMap  map[string]*Object
	pathMap map[string]*Object
	lock    sync.Mutex
	verbose bool
}

func (os *ObjectStore) PreloadBlob(hexname string, data []byte) error {
	if os.verbose {
		fmt.Printf("objstore: preload: %s... %d\n", hexname[:8], len(data))
	}
	o, err := NewObject(data)
	if err != nil {
		if os.verbose {
			fmt.Printf("objstore: preload: %s... %v\n", hexname[:8], err)
		}
		return err
	}
	os.refMap[hexname] = o
	return nil
}

func NewObjectStore(path string) *ObjectStore {
	os := &ObjectStore{
		refMap:  make(map[string]*Object),
		pathMap: make(map[string]*Object),
		verbose: true,
	}

	os.bs = NewBlobStore(path, os)
	return os
}

func (os *ObjectStore) GetByRef(ref string) *Object {
	os.lock.Lock()
	o := os.refMap[ref]
	os.lock.Unlock()
	return o
}

func (os *ObjectStore) GetByPath(path string) *Object {
	os.lock.Lock()
	o := os.pathMap[path]
	os.lock.Unlock()
	return o
}

func (os *ObjectStore) Put(obj *Object) error {
	// TODO: validate name, etc

	if obj == nil {
		return ErrBadObject
	}

	data := obj.Serialize()
	hash := sha256.New()
	hash.Write(data)
	obj.SelfRef = string(hash.Sum(nil))

	os.lock.Lock()
	defer os.lock.Unlock()

	if os.pathMap[obj.Path] != nil {
		return ErrExists
	}

	os.pathMap[obj.Path] = obj
	os.refMap[obj.SelfRef] = obj

	// commit to disk (after lock?)
	return nil
}

func (os *ObjectStore) Replace(obj *Object, old *Object) error {
	// TODO: validate name, etc

	if (obj == nil) || (old == nil) {
		return ErrBadObject
	}

	obj.ParentRef = old.SelfRef
	obj.Parent = old

	data := obj.Serialize()
	hash := sha256.New()
	hash.Write(data)
	obj.SelfRef = string(hash.Sum(nil))

	os.lock.Lock()
	defer os.lock.Unlock()

	checkOldRef := os.refMap[old.SelfRef]
	checkOldPath := os.pathMap[obj.Path]

	if checkOldRef == nil {
		return ErrNotFound
	}
	if checkOldPath != old {
		return ErrExists
	}

	os.refMap[obj.SelfRef] = obj
	os.pathMap[obj.Path] = obj
	old.RefCount++

	// commit to disk (after lock?)
	return nil
}
