package main

import "os"

// fairNativeQueriesDir is the native query-set directory (native-queries/<records>/):
// FAIR_QUERY_DIR, which the experiment scripts export for experiment 1, or
// FAIR_NATIVE_QUERIES_DIR for the ablation and the cloud demo. Empty keeps the
// fixed clustered-2/scattered placements.
func fairNativeQueriesDir() string {
	if dir := os.Getenv("FAIR_QUERY_DIR"); dir != "" {
		return dir
	}
	return os.Getenv("FAIR_NATIVE_QUERIES_DIR")
}
