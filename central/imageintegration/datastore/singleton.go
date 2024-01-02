package datastore

import (
	"context"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/central/imageintegration/search"
	"github.com/stackrox/rox/central/imageintegration/store"
	pgStore "github.com/stackrox/rox/central/imageintegration/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/sac"
	scannerTypes "github.com/stackrox/rox/pkg/scanners/types"
	"github.com/stackrox/rox/pkg/sync"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	once sync.Once

	dataStore DataStore
)

func initializeIntegrations(iiStore store.Store) {
	ctx := sac.WithGlobalAccessScopeChecker(context.Background(), sac.AllowAllAccessScopeChecker())
	iis, err := iiStore.GetAll(ctx)
	utils.CrashOnError(err)
	// If we are starting from scratch in online-mode, add the default image integrations.
	if !env.OfflineModeEnv.BooleanSetting() && len(iis) == 0 {
		// Add default integrations
		for _, ii := range store.DefaultImageIntegrations {
			utils.Should(iiStore.Upsert(ctx, ii))
		}
	}

	deleteAutogeneratedRegistries(ctx, iiStore, iis)

	setupScannerV4Integration(ctx, iiStore, iis)
}

func deleteAutogeneratedRegistries(ctx context.Context, iiStore store.Store, iis []*storage.ImageIntegration) {
	autogenDisabled := env.AutogeneratedRegistriesDisabled.BooleanSetting()
	sourcedAutogenDisabled := !features.SourcedAutogeneratedIntegrations.Enabled()

	if !autogenDisabled && !sourcedAutogenDisabled {
		// Both autogenerated registry types are enabled, short-circuit.
		return
	}

	if len(iis) == 0 {
		// No integrations to process, short-circuit.
		return
	}

	log.Infof("[STARTUP] Starting deletion of autogenerated image integrations (autogen disabled [%t], 'sourced' autogen disabled [%t])", autogenDisabled, sourcedAutogenDisabled)

	var attempted, deleted int
	for _, ii := range iis {
		if !ii.GetAutogenerated() {
			continue
		}

		if autogenDisabled || (sourcedAutogenDisabled && ii.GetSource() != nil) {
			attempted++
			// Use Should so release versions do not panic.
			if err := utils.ShouldErr(iiStore.Delete(ctx, ii.GetId())); err == nil {
				deleted++
			}
		}
	}
	if attempted > 0 {
		log.Infof("Successfully deleted %d out of %d image integration(s)", deleted, attempted)
	} else {
		log.Info("No eligible autogenerated image integrations found for deletion")
	}

	log.Info("Completed deletion of image integrations")
}

// setupScannerV4Integration will ensure the default Scanner V4 integration exists if
// Scanner V4 is installed/enabled (forces opt-in). If Scanner V4 is not installed (or is disabled)
// will delete all Scanner V4 integrations.
func setupScannerV4Integration(ctx context.Context, iiStore store.Store, iis []*storage.ImageIntegration) {
	keepDefault := true // for readability.

	// If Scanner V4 is not installed delete the associated integration(s).
	if !features.ScannerV4Enabled.Enabled() {
		deleteScannerV4Integrations(ctx, iiStore, iis, !keepDefault)
		return
	}

	// Create the default Scanner V4 integration if it doesn't exist.
	createDefaultScannerV4Integration(ctx, iiStore)

	// Delete all but the default Scanner V4 integration (should be none).
	deleteScannerV4Integrations(ctx, iiStore, iis, keepDefault)
}

// createDefaultScannerV4Integration will create the default Scanner V4 integration if it does
// not currently exist.
func createDefaultScannerV4Integration(ctx context.Context, iiStore store.Store) {
	if _, exists, err := iiStore.Get(ctx, store.DefaultScannerV4Integration.GetId()); err != nil {
		utils.Should(errors.Wrap(err, "unable to detect if default Scanner V4 integration exists"))
		return
	} else if exists {
		// Nothing to do, integration exists.
		return
	}

	log.Infof("Upserting default Scanner V4 integration %q (%v)", store.DefaultScannerV4Integration.GetName(), store.DefaultScannerV4Integration.GetId())
	err := iiStore.Upsert(ctx, store.DefaultScannerV4Integration)
	utils.Should(errors.Wrap(err, "unable to upsert default ScannerV4 integration"))
}

// deleteScannerV4Integrations will delete all Scanner V4 integrations except for the
// the default integration if keepDefault is true.
func deleteScannerV4Integrations(ctx context.Context, iiStore store.Store, iis []*storage.ImageIntegration, keepDefault bool) {
	for _, ii := range iis {
		if ii.GetType() != scannerTypes.ScannerV4 {
			// Ignore non Scanner V4 integrations.
			continue
		}

		if keepDefault && ii.GetId() == store.DefaultScannerV4Integration.GetId() {
			// Keep the default Scanner V4 integration.
			continue
		}

		if err := iiStore.Delete(ctx, ii.GetId()); err != nil {
			utils.Should(errors.Wrapf(err, "failed to delete Scanner V4 integration %q (%s)", ii.GetName(), ii.GetId()))
			continue
		}

		log.Infof("Deleted Scanner V4 integration %q (%s)", ii.GetName(), ii.GetId())
	}
}

func initialize() {
	// Create underlying store and datastore.
	storage := pgStore.New(globaldb.GetPostgres())

	initializeIntegrations(storage)
	searcher := search.New(storage, pgStore.NewIndexer(globaldb.GetPostgres()))
	dataStore = New(storage, searcher)
}

// Singleton provides the interface for non-service external interaction.
func Singleton() DataStore {
	once.Do(initialize)
	return dataStore
}
