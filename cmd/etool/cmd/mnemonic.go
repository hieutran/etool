package cmd

import (
	"fmt"

	"github.com/hieutran/etool/pkg/validator"
	"github.com/spf13/cobra"
)

var generateMnemonicCmd = &cobra.Command{
	Use:   "generate-mnemonic",
	Short: "Generate a BIP39 mnemonic",
	Long:  `Generates a secure BIP39 mnemonic phrase (24 words).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("🎲 Generating BIP39 mnemonic...\n\n")

		mnemonic, err := validator.GenerateMnemonic()
		if err != nil {
			return fmt.Errorf("failed to generate mnemonic: %w", err)
		}

		fmt.Printf("⚠️  SECURITY WARNING: The mnemonic will be displayed. Ensure no one else can see your screen.\n")
		fmt.Printf("⚠️  IMPORTANT: Save this mnemonic securely and never share it!\n")
		fmt.Printf("⚠️  Anyone with this mnemonic can control your validators!\n\n")
		fmt.Printf("📋 Mnemonic:\n")
		fmt.Printf("   %s\n\n", mnemonic)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateMnemonicCmd)
}
