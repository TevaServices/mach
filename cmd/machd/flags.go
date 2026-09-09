package main

import "flag"

func flagSet() *flag.FlagSet { return flag.NewFlagSet("machd", flag.ContinueOnError) }

func envOr(key, def string) string {
	if v := osGetenv(key); v != "" {
		return v
	}
	return def
}