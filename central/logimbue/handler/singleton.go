package handler

import (
	"net/http"

	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/logimbue/store"
	"github.com/stackrox/rox/pkg/sync"
)

var (
	once sync.Once

	storage store.Store

	ha http.Handler
)

func initialize() {
	storage = store.New(globaldb.GetGlobalDB())

	ha = New(storage)
}

// Singleton returns the HTTP handler to use to serve HTTP requests.
func Singleton() http.Handler {
	once.Do(initialize)
	return ha
}
