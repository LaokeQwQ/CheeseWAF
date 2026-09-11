// Package bolt preserves the small legacy API surface used by
// raft-boltdb's migration helper while delegating storage to maintained
// bbolt. The aliases keep one implementation and inherit bbolt's supported
// platform set, including LoongArch.
package bolt

import bbolt "go.etcd.io/bbolt"

type DB = bbolt.DB
type Options = bbolt.Options
type Tx = bbolt.Tx
type Bucket = bbolt.Bucket
type Cursor = bbolt.Cursor
type Stats = bbolt.Stats

var Open = bbolt.Open
