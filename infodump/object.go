// Copyright 2023 Brian Swetland <swetland@frotz.net>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package infodump

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var validPathRe = regexp.MustCompile(`^[a-z0-9_:-]+(/[a-z0-9_:-]+)*$`)

func IsValidPath(path string) bool {
	return validPathRe.MatchString(path)
}

// Newly created objects are mutable.  Objects obtained
// from the Object store are not (setters have no effect).

type Object interface {
	Type() string    // mime type
	BlobRef() string // reference to current content
	CTime() int64    // creation time in UnixNanos
	MTime() int64    // modification time in UnixNanos
	Tags() []string  // associated tags
	RefCount() int32 // number of parents
	SelfRef() string // reference to ourself in blobstore
	UniqRef() string // reference to a uniq object
	Parent() Object

	SetType(mt string)
	SetBlob(ref string)
	SetCTime(t int64)
	SetMTime(t int64)
	SetTags(tags []string)
	SetAttr(name string, value string)
	SetUniq(ref string)

	Serialize() []byte

	Private() *object
}

func (o *object) Type() string    { return o.mimetype }
func (o *object) BlobRef() string { return o.blobRef }
func (o *object) CTime() int64    { return o.cTime }
func (o *object) MTime() int64    { return o.mTime }
func (o *object) Tags() []string  { return o.tags }
func (o *object) RefCount() int32 { return o.refCount }
func (o *object) SelfRef() string { return o.selfRef }
func (o *object) UniqRef() string { return o.uniqRef }
func (o *object) Parent() Object  { return o.parent }

func (o *object) SetType(mt string) {
	if o.mutable {
		o.mimetype = mt
	}
}

func (o *object) SetBlob(ref string) {
	if o.mutable {
		o.blobRef = ref
	}
}

func (o *object) SetTags(tags []string) {
	// TODO: copy?
	if o.mutable {
		o.tags = tags
	}
}

func (o *object) SetAttr(name string, value string) {
	if !o.mutable {
		return
	}
	if o.attrs == nil {
		o.attrs = map[string]string{
			name: value,
		}
	} else {
		o.attrs[name] = value
	}
}

func (o *object) SetUniq(ref string) {
	if o.mutable {
		o.uniqRef = ref
	}
}

func (o *object) SetCTime(t int64) {
	if o.mutable {
		o.cTime = t
	}
}

func (o *object) SetMTime(t int64) {
	if o.mutable {
		o.mTime = t
	}
}

func (o *object) Serialize() []byte {
	return o.pack()
}

func (o *object) Private() *object { return o }

func NewObjectFromJSON(bytes []byte) (Object, error) {
	return unpackObject(bytes)
}

func NewObject(parent Object) Object {
	now := time.Now().UnixNano()

	if parent == nil {
		o := &object{
			cTime:   now,
			mTime:   now,
			mutable: true,
		}
		return o
	}

	p := parent.Private()
	o := &object{
		mimetype: p.mimetype,
		blobRef:  p.blobRef,
		cTime:    p.cTime,
		mTime:    now,
		tags:     p.tags,  // TODO: copy
		attrs:    p.attrs, // TODO: copy
		parent:   p,
		mutable:  true,
	}
	return o
}

type object struct {
	mimetype  string
	selfRef   string
	blobRef   string
	uniqRef   string
	parentRef string
	cTime     int64
	mTime     int64
	tags      []string
	attrs     map[string]string
	entries   map[string]string

	refCount int32
	parent   *object
	mutable  bool // may this object be modified?
}

// for JSON deserializing
type anyobject struct {
	Type      string
	Path      string
	BlobRef   string
	ParentRef string
	CTime     string
	MTime     string
	Tags      []string
	Attrs     map[string]string
	InfoHash  string
}

// magic values
var infodump = []byte("{\"infodump\":1,")
var infohash = []byte(",\"infohash\":\"")

// magic values without the leading/trailing commas
var infodumpNoComma = infodump[:len(infodump)-1]
var infohashNoComma = infohash[2:]

func unpackObject(b []byte) (o *object, err error) {
	var t anyobject

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

	o = &object{
		mimetype:  t.Type,
		blobRef:   t.BlobRef,
		parentRef: t.ParentRef,
		cTime:     ctime,
		mTime:     mtime,
		tags:      t.Tags,
		attrs:     t.Attrs,
		selfRef:   hex.EncodeToString(sum),
		mutable:   false,
	}
	return
}

func (o *object) pack() []byte {
	// string maps get marshalled into json in key sort order
	payload := make(map[string]interface{})
	payload["type"] = o.mimetype

	// uniq objects are special and never have non-attr fields
	if o.mimetype != "infodump/uniq" {
		payload["blobref"] = o.blobRef
		payload["parentref"] = o.parentRef
		payload["ctime"] = strconv.FormatInt(o.cTime, 10)
		payload["mtime"] = strconv.FormatInt(o.mTime, 10)
		if o.tags != nil {
			payload["tags"] = o.tags
		}
	}
	if o.attrs != nil {
		payload["attrs"] = o.attrs
	}

	return serialize(payload)
}

func serialize(payload interface{}) []byte {
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

type ObjectStore struct {
	bs      BlobStore
	refMap  map[string]*object
	lock    sync.Mutex
	verbose bool
}

func (os *ObjectStore) PreloadBlob(hexname string, data []byte) error {
	if os.verbose {
		fmt.Printf("objstore: preload: %s... %d\n", hexname[:8], len(data))
	}
	o, err := unpackObject(data)
	if err != nil {
		if os.verbose {
			fmt.Printf("objstore: preload: %s... %v\n", hexname[:8], err)
		}
		return err
	}
	os.refMap[hexname] = o
	return nil
}

func NewObjectStore(bs BlobStore) *ObjectStore {
	return &ObjectStore{
		bs:      bs,
		refMap:  make(map[string]*object),
		verbose: true,
	}
}

func (os *ObjectStore) Get(ref string) Object {
	os.lock.Lock()
	o := os.refMap[ref]
	os.lock.Unlock()
	return o
}

func (os *ObjectStore) Put(obj Object) error {
	if obj == nil {
		return ErrBadObject
	}
	return os.put(obj.Private())
}

func (os *ObjectStore) newUniq(root bool) (o Object, err error) {
	rval := make([]byte, 32)
	if _, err = rand.Read(rval); err != nil {
		return
	}

	o = NewObject(nil)
	o.SetType("infodump/uniq")
	o.SetAttr("random", hex.EncodeToString(rval))
	if root {
		o.SetAttr("root", "true")
	}
	if err = os.Put(o); err != nil {
		o = nil
	}
	return
}

func (os *ObjectStore) NewUniq() (o Object, err error) {
	return os.newUniq(false)
}

func (os *ObjectStore) NewUniqRoot() (o Object, err error) {
	return os.newUniq(true)
}

func (os *ObjectStore) put(obj *object) error {
	if !obj.mutable {
		return ErrBadObject
	}
	// TODO: copy to prevent mutation via race condition?
	obj.mutable = false

	data := obj.pack()

	// write to the blobstore and obtain a blobref
	ref, err := os.bs.Put(data)
	if err != nil {
		return err
	}
	obj.selfRef = ref

	// TODO: anything to do should this collide?
	// (the chances of a non-identical object colliding seems... very unlikely)
	os.lock.Lock()
	os.refMap[ref] = obj
	os.lock.Unlock()

	return nil
}
