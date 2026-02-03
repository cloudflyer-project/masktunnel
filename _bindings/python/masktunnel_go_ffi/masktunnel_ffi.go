package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct masktunnel_buf {
    uint8_t* data;
    int64_t len;
} masktunnel_buf;
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
	"unsafe"

	masktunnel "github.com/cloudflyer-project/masktunnel"
)

func writeBuf(out *C.masktunnel_buf, b []byte) *C.char {
	if out == nil {
		return errStr(errors.New("out is nil"))
	}
	if len(b) == 0 {
		out.data = nil
		out.len = 0
		return nil
	}
	ptr := C.malloc(C.size_t(len(b)))
	if ptr == nil {
		return errStr(errors.New("malloc failed"))
	}
	buf := unsafe.Slice((*byte)(ptr), len(b))
	copy(buf, b)
	out.data = (*C.uint8_t)(ptr)
	out.len = C.int64_t(len(b))
	return nil
}

type handle uint64

var (
	mu            sync.RWMutex
	nextHandle    handle = 1
	serverHandles        = map[handle]*masktunnel.ServerHandle{}
)

func newServerHandle(v *masktunnel.ServerHandle) handle {
	mu.Lock()
	h := nextHandle
	nextHandle++
	serverHandles[h] = v
	mu.Unlock()
	return h
}

func getServer(h handle) (*masktunnel.ServerHandle, error) {
	mu.RLock()
	v := serverHandles[h]
	mu.RUnlock()
	if v == nil {
		return nil, errors.New("invalid server handle")
	}
	return v, nil
}

func delServer(h handle) {
	mu.Lock()
	delete(serverHandles, h)
	mu.Unlock()
}

func errStr(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

func cstr(s string) *C.char {
	return C.CString(s)
}

//export masktunnel_free
func masktunnel_free(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}

//export masktunnel_buf_free
func masktunnel_buf_free(b C.masktunnel_buf) {
	if b.data != nil {
		C.free(unsafe.Pointer(b.data))
	}
}

//export masktunnel_version
func masktunnel_version() *C.char {
	return cstr("1.0.21")
}

//export masktunnel_seconds
func masktunnel_seconds() C.int64_t {
	return C.int64_t(int64(time.Second))
}

//export masktunnel_parse_duration
func masktunnel_parse_duration(s *C.char, out *C.int64_t) *C.char {
	if out == nil {
		return errStr(errors.New("out is nil"))
	}
	d, err := time.ParseDuration(C.GoString(s))
	if err != nil {
		return errStr(err)
	}
	*out = C.int64_t(int64(d))
	return nil
}

//export masktunnel_wait_for_log_entries
func masktunnel_wait_for_log_entries(timeout_ms C.int64_t, out *C.masktunnel_buf) *C.char {
	if out == nil {
		return errStr(errors.New("out is nil"))
	}
	entries := masktunnel.WaitForLogEntries(int64(timeout_ms))
	data, err := json.Marshal(entries)
	if err != nil {
		return errStr(err)
	}
	return writeBuf(out, data)
}

//export masktunnel_cancel_log_waiters
func masktunnel_cancel_log_waiters() {
	masktunnel.CancelLogWaiters()
}

//export masktunnel_server_create
func masktunnel_server_create(opts_json *C.char) C.uint64_t {
	var opts masktunnel.ServerOption
	if err := json.Unmarshal([]byte(C.GoString(opts_json)), &opts); err != nil {
		return 0
	}
	srv := masktunnel.NewServerHandle(&opts)
	return C.uint64_t(newServerHandle(srv))
}

//export masktunnel_server_start
func masktunnel_server_start(h C.uint64_t) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	return errStr(srv.Start())
}

//export masktunnel_server_start_background
func masktunnel_server_start_background(h C.uint64_t) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	return errStr(srv.StartBackground())
}

//export masktunnel_server_stop
func masktunnel_server_stop(h C.uint64_t) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	return errStr(srv.Stop())
}

//export masktunnel_server_close
func masktunnel_server_close(h C.uint64_t) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	err = srv.Close()
	if err == nil {
		delServer(handle(h))
	}
	return errStr(err)
}

//export masktunnel_server_addr
func masktunnel_server_addr(h C.uint64_t) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	return cstr(srv.Addr())
}

//export masktunnel_server_reset_sessions
func masktunnel_server_reset_sessions(h C.uint64_t, out *C.int) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	count := srv.ResetSessions()
	*out = C.int(count)
	return nil
}

//export masktunnel_server_set_upstream_proxy
func masktunnel_server_set_upstream_proxy(h C.uint64_t, proxy *C.char) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	return errStr(srv.SetUpstreamProxy(C.GoString(proxy)))
}

//export masktunnel_server_get_ca_pem
func masktunnel_server_get_ca_pem(h C.uint64_t, out *C.masktunnel_buf) *C.char {
	srv, err := getServer(handle(h))
	if err != nil {
		return errStr(err)
	}
	pem := srv.GetCAPEM()
	return writeBuf(out, pem)
}

func main() {}
