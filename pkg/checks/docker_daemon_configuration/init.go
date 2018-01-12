package dockerdaemonconfiguration

import "bitbucket.org/stack-rox/apollo/pkg/checks"

func init() {
	checks.AddToRegistry(
		// Part 2
		NewNetworkRestrictionBenchmark(), // 2.1
		NewLogLevelBenchmark(),
		NewIPTablesEnabledBenchmark(),
		NewInsecureRegistriesBenchmark(),
		NewAUFSBenchmark(), // 2.5
		NewTLSVerifyBenchmark(),
		NewDefaultUlimitBenchmark(),
		NewUserNamespaceBenchmark(),
		NewCgroupUsageBenchmark(),
		NewBaseDeviceSizeBenchmark(), // 2.10
		NewAuthorizationPluginBenchmark(),
		NewRemoteLoggingBenchmark(),
		NewDisableLegacyRegistryBenchmark(),
		NewLiveRestoreEnabledBenchmark(),
		NewDisableUserlandProxyBenchmark(), // 2.15
		NewDaemonWideSeccompBenchmark(),
		NewDisableExperimentalBenchmark(),
		NewRestrictContainerPrivilegesBenchmark(),
	)
}
