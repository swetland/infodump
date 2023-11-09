// Copyright 2023 Brian Swetland <swetland@frotz.net>
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package infodump

type Error string

func (e Error) Error() string {
        return string(e)
}

const ErrBadMagic = Error("bad magic value")
const ErrBadHash = Error("missing or invalid hash")
const ErrBadName = Error("invalid name")
const ErrNotFound = Error("does not exist")
const ErrExists = Error("already exists")
const ErrBadObject = Error("invalid object")

