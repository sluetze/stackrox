package postgres

//go:generate pg-table-bindings-wrapper --type=storage.NetworkPolicy --table=networkpolicies --search-category NETWORK_POLICIES --migration-seq 32 --migrate-from boltdb --references storage.Cluster
