package pam

import "sync"

var cb struct {
	sync.Mutex
	m map[int]interface{}
	c int
}

func cbAdd(v interface{}) int {
	cb.Lock()
	defer cb.Unlock()
	if cb.m == nil {
		cb.m = make(map[int]interface{})
	}
	cb.c++
	cb.m[cb.c] = v
	return cb.c
}

func cbGet(c int) interface{} {
	cb.Lock()
	defer cb.Unlock()
	v := cb.m[c]
	if v == nil {
		panic("Callback pointer not found")
	}
	return v
}
