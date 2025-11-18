package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/hieutran/etool/pkg/nodekey"
	"github.com/spf13/cobra"
)

var generateNodekeyCmd = &cobra.Command{
	Use:   "generate-nodekey",
	Short: "Generate node key only",
	Long:  `Generates a node key for P2P networking identification.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("🔑 Generating node key...\n")

		gen := nodekey.NewGenerator()
		outputPath := filepath.Join(outputDir, "nodekey")

		nodeKey, err := gen.GenerateToFile(outputPath)
		if err != nil {
			return fmt.Errorf("failed to generate node key: %w", err)
		}

		fmt.Printf("✅ Node key saved to %s\n", outputPath)
		fmt.Printf("ℹ️  Node ID: %s\n", nodeKey.NodeID)
		fmt.Printf("ℹ️  Public Key: %s\n", nodeKey.PublicKey)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateNodekeyCmd)
}
