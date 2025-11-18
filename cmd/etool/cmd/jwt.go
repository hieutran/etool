package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/hieutran/etool/pkg/jwt"
	"github.com/spf13/cobra"
)

var generateJWTCmd = &cobra.Command{
	Use:   "generate-jwt",
	Short: "Generate JWT secret only",
	Long:  `Generates a JWT secret for secure communication between execution and consensus layers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("📝 Generating JWT secret...\n")

		gen := jwt.NewGenerator()
		outputPath := filepath.Join(outputDir, "jwt.hex")

		if err := gen.GenerateToFile(outputPath); err != nil {
			return fmt.Errorf("failed to generate JWT secret: %w", err)
		}

		fmt.Printf("✅ JWT secret saved to %s\n", outputPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateJWTCmd)
}
