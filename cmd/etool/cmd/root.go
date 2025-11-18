package cmd

import (
	"github.com/spf13/cobra"
)

var (
	outputDir string
)

var rootCmd = &cobra.Command{
	Use:   "eth-genesis-tool",
	Short: "A production-grade tool for generating Ethereum genesis configurations",
	Long: `eth-genesis-tool is a comprehensive utility for generating all necessary
files to bootstrap an Ethereum network, including execution layer genesis,
consensus layer genesis, validator keystores, and deposit data.

Based on logic from:
- github.com/ethpandaops/ethereum-genesis-generator
- github.com/protolambda/eth2-val-tools`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", "./output", "Output directory for generated files")
}
