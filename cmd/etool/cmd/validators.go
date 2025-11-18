package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/hieutran/etool/pkg/validator"
	"github.com/spf13/cobra"
)

var (
	validatorMnemonic    string
	validatorCount       uint64
	validatorStartIndex  uint64
	generateDepositData  bool
	validatorForkVersion string
)

var generateValidatorsCmd = &cobra.Command{
	Use:   "generate-validators",
	Short: "Generate validator keystores only",
	Long:  `Generates validator keystores, passwords, and optionally deposit data.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate validatorCount
		if validatorCount == 0 {
			return fmt.Errorf("validatorCount must be > 0")
		}

		fmt.Printf("👥 Generating %d validator keystores (production-grade BLS)...\n", validatorCount)

		// Generate or use provided mnemonic
		var mnemonic string
		var err error

		if validatorMnemonic == "" {
			fmt.Printf("🎲 Generating BIP39 mnemonic...\n")
			mnemonic, err = validator.GenerateMnemonic()
			if err != nil {
				return fmt.Errorf("failed to generate mnemonic: %w", err)
			}
			fmt.Printf("   ⚠️  SECURITY WARNING: The mnemonic will be displayed. Ensure no one else can see your screen.\n")
			fmt.Printf("   ⚠️  IMPORTANT: Save this mnemonic securely and never share it!\n")
			fmt.Printf("   📋 Mnemonic: %s\n\n", mnemonic)

			// Save mnemonic
			mnemonicPath := filepath.Join(outputDir, "mnemonic.txt")
			if err := validator.SavePassword(mnemonic, mnemonicPath); err != nil {
				return fmt.Errorf("failed to save mnemonic: %w", err)
			}
			fmt.Printf("   ✅ Mnemonic saved to %s\n\n", mnemonicPath)
		} else {
			mnemonic = validatorMnemonic
			if err := validator.ValidateMnemonic(mnemonic); err != nil {
				return fmt.Errorf("invalid mnemonic: %w", err)
			}
		}

		// Generate keystores (always use simplified for keystore files)
		gen, err := validator.NewGenerator(mnemonic)
		if err != nil {
			return fmt.Errorf("failed to create validator generator: %w", err)
		}

		keystoresDir := filepath.Join(outputDir, "keystores")
		keystores, err := gen.GenerateKeystores(validatorStartIndex, validatorCount, keystoresDir, nil)
		if err != nil {
			return fmt.Errorf("failed to generate keystores: %w", err)
		}

		fmt.Printf("✅ Generated %d keystores in %s\n", len(keystores), keystoresDir)

		// Generate deposit data if requested
		if generateDepositData {
			fmt.Printf("\n📋 Generating deposit data...\n")
			fmt.Printf("   🔐 Using production-grade BLS12-381 cryptography...\n")

			depositGen, err := validator.NewBLSDepositGenerator(validatorForkVersion, networkName, validator.BLSWithdrawal)
			if err != nil {
				return fmt.Errorf("failed to create BLS deposit generator: %w", err)
			}

			depositList, err := depositGen.GenerateDepositDataList(mnemonic, validatorStartIndex, validatorCount)
			if err != nil {
				return fmt.Errorf("failed to generate BLS deposit data: %w", err)
			}

			depositPath := filepath.Join(outputDir, "deposit_data.json")
			if err := validator.SaveDepositData(depositList, depositPath); err != nil {
				return fmt.Errorf("failed to save deposit data: %w", err)
			}

			fmt.Printf("   ✅ Production BLS deposit data saved to %s\n", depositPath)
		}

		fmt.Printf("\n✨ Generated with production-grade BLS12-381 cryptography\n")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateValidatorsCmd)

	generateValidatorsCmd.Flags().StringVar(&validatorMnemonic, "mnemonic", "", "BIP39 mnemonic (will generate if not provided)")
	generateValidatorsCmd.Flags().Uint64Var(&validatorCount, "count", 64, "Number of validators to generate")
	generateValidatorsCmd.Flags().Uint64Var(&validatorStartIndex, "start-index", 0, "Starting validator index")
	generateValidatorsCmd.Flags().BoolVar(&generateDepositData, "with-deposits", false, "Also generate deposit_data.json")
	generateValidatorsCmd.Flags().StringVar(&validatorForkVersion, "fork-version", "0x00000001", "Genesis fork version")
}
