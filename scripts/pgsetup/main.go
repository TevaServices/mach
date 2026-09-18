// Command pgsetup prepares a Postgres instance for the end-to-end suite.
//
// The e2e runs against a file by default, where "a fresh database" is just a new
// path in a temp dir. Postgres has no such thing, so this does the equivalent
// explicitly, and prints the DSN for the database it prepared — because deriving
// one by editing a URL in shell is exactly the kind of string surgery that
// quietly produces a DSN pointing somewhere else.
//
// It is a test helper, not part of the product: the control plane creates its own
// schema on first connect, and this only ever drops things.
//
//	pgsetup --reset  <dsn>           wipe the schema in the DSN's own database
//	pgsetup --create <dsn> <name>    drop and recreate database <name>
//
// Both print the DSN to use. Run it only against a throwaway server: --reset
// discards every table in the database it is pointed at.
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/jackc/pgx/v5"
)

func usage() {
	fmt.Fprint(os.Stderr, `pgsetup — prepare a Postgres database for the e2e suite

  pgsetup --reset  <dsn>           drop and recreate the schema in the DSN's database
  pgsetup --create <dsn> <name>    drop and recreate database <name>, then print its DSN

Both print the DSN to use. This DISCARDS data: point it at a throwaway server.
`)
}

func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	dsn := args[1]
	ctx := context.Background()

	switch args[0] {
	case "--reset":
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			fail(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
			fail(fmt.Errorf("drop schema: %w", err))
		}
		if _, err := conn.Exec(ctx, `CREATE SCHEMA public`); err != nil {
			fail(fmt.Errorf("create schema: %w", err))
		}
		fmt.Println(dsn)

	case "--create":
		if len(args) != 3 {
			usage()
			os.Exit(2)
		}
		name := strings.TrimSpace(args[2])
		if name == "" || strings.ContainsAny(name, `"' ;`) {
			fail(fmt.Errorf("%q is not a usable database name", name))
		}
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			fail(err)
		}
		defer conn.Close(ctx)
		// Identifiers cannot be parameterised, which is why the name is checked
		// above rather than quoted and hoped for.
		if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+name); err != nil {
			fail(fmt.Errorf("drop database %s: %w", name, err))
		}
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+name); err != nil {
			fail(fmt.Errorf("create database %s: %w", name, err))
		}
		derived, err := dsnForDatabase(dsn, name)
		if err != nil {
			fail(err)
		}
		fmt.Println(derived)

	default:
		usage()
		os.Exit(2)
	}
}

// dsnForDatabase returns dsn with its database name replaced. Parsed as a URL
// rather than rewritten with a string edit, so userinfo, query options and any
// percent-encoding survive intact.
func dsnForDatabase(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("not a usable DSN: %w", err)
	}
	u.Path = path.Join("/", name)
	return u.String(), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "pgsetup: "+err.Error())
	os.Exit(1)
}
