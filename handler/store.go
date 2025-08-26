package handler

import (
	"errors"
	"sync"
)

var (
	ErrAlreadyExists = errors.New("already exists")
	ErrNotFound      = errors.New("not found")
)

var clientStore = NewStore[string, *Client]("client")
var sessionStore = NewStore[string, string]("session")
var authcodeStore = NewStore[string, AuthCode]("authcode")

type Store[K comparable, V any] struct {
	mux  *sync.Mutex
	Name string
	Data map[K]V
}

func NewStore[K comparable, V any](name string) *Store[K, V] {
	return &Store[K, V]{
		mux:  &sync.Mutex{},
		Name: name,
		Data: make(map[K]V),
	}
}

func (s *Store[K, V]) Add(key K, value V) error {
	if s.exists(key) {
		return ErrAlreadyExists
	}
	s.mux.Lock()
	s.Data[key] = value
	s.mux.Unlock()

	return nil
}

func (s *Store[K, V]) Delete(key K) error {
	if !s.exists(key) {
		return ErrNotFound
	}
	s.mux.Lock()
	delete(s.Data, key)
	s.mux.Unlock()

	return nil
}

func (s *Store[K, V]) exists(key K) bool {
	_, ok := s.Data[key]
	return ok
}
