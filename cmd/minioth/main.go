package main

import (
	"flag"
	"log"
	"path/filepath"

	"github.com/kyri56xcaesar/minioth/internal/domain"
	"github.com/kyri56xcaesar/minioth/internal/server"
	"github.com/kyri56xcaesar/minioth/internal/store"
)

func main() {
	backend := flag.String("backend", "db", `storage backend to use: "db" (SQLite) or "plain" (flat files, see internal/store/plain.go)`)
	dataDir := flag.String("data-dir", "data", "base directory for on-disk state: the SQLite db (unless -db-path overrides it) and, under a \"plain\" subdirectory, the plain backend's flat files")
	dbPath := flag.String("db-path", "", `SQLite file path (only used when -backend="db"; defaults to "<data-dir>/minioth.db")`)
	conf := flag.String("conf", "minioth.env", "path to the .env config file")
	flag.Parse()

	if *dbPath == "" {
		*dbPath = filepath.Join(*dataDir, "minioth.db")
	}
	store.SetPlainDataDir(filepath.Join(*dataDir, "plain"))

	// Load config and apply its process-wide side effects (JWT signing
	// state, HASH_COST, password policy) before constructing anything that
	// might use them — domain.NewMinioth below seeds a root user, which
	// hashes a password.
	cfg := server.Bootstrap(*conf)

	var handler domain.MiniothHandler
	switch *backend {
	case "db":
		handler = &store.DBHandler{DBpath: *dbPath}
	case "plain":
		handler = &store.PlainHandler{}
	default:
		log.Fatalf(`unknown -backend %q: must be "db" or "plain"`, *backend)
	}

	root := domain.User{
		Name:     cfg.RootUsername,
		Password: domain.Password{Hashpass: cfg.RootPassword},
	}
	m := domain.NewMinioth(root, handler)
	srv := server.NewMService(&m, cfg)
	srv.ServeHTTP()
}
