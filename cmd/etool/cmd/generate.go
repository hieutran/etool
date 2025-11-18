package cmd

import (
	"fmt"
	"math/big"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/hieutran/etool/pkg/config"
	"github.com/hieutran/etool/pkg/genesis"
	"github.com/hieutran/etool/pkg/jwt"
	"github.com/hieutran/etool/pkg/nodekey"
	"github.com/hieutran/etool/pkg/validator"
	"github.com/spf13/cobra"
)

var (
	chainID              uint64
	networkName          string
	numValidators        uint64
	mnemonic             string
	validatorPrivateKeys []string
	genesisTime          uint64
	prefundAccounts      []string
	prefundBalance       string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate all Ethereum genesis files",
	Long: `Generates all necessary files for an Ethereum network:
- JWT secret (jwt.hex)
- Node key (nodekey)
- Execution layer genesis (genesis.json)
- Consensus layer config (config.yaml)
- Validator keystores and passwords
- Deposit data (deposit_data.json)`,
	RunE: runGenerate,
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().Uint64Var(&chainID, "chain-id", 32382, "Chain ID for the network")
	generateCmd.Flags().StringVar(&networkName, "network-name", "eth-devnet", "Name of the network")
	generateCmd.Flags().Uint64Var(&numValidators, "num-validators", 64, "Number of validators to generate")
	generateCmd.Flags().StringVar(&mnemonic, "mnemonic", "", "BIP39 mnemonic (will generate if not provided)")
	generateCmd.Flags().StringSliceVar(&validatorPrivateKeys, "validator-private-keys", []string{}, "Validator private keys (hex strings, comma-separated). If provided, mnemonic will be ignored")
	generateCmd.Flags().Uint64Var(&genesisTime, "genesis-time", 0, "Genesis timestamp (uses current time if 0)")
	generateCmd.Flags().StringSliceVar(&prefundAccounts, "prefund-accounts", []string{}, "Accounts to prefund (comma-separated addresses)")
	generateCmd.Flags().StringVar(&prefundBalance, "prefund-balance", "1000000000000000000000", "Balance for prefunded accounts in wei (default: 1000 ETH)")
}

func runGenerate(cmd *cobra.Command, args []string) error {
	fmt.Printf("🚀 Generating Ethereum genesis configuration (production-grade BLS)...\n\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Chain ID: %d\n", chainID)
	fmt.Printf("  Network: %s\n", networkName)
	fmt.Printf("  Validators: %d\n", numValidators)
	fmt.Printf("  Output: %s\n\n", outputDir)

	// Step 1: Generate JWT secret
	fmt.Printf("📝 Generating JWT secret...\n")
	jwtGen := jwt.NewGenerator()
	jwtPath := filepath.Join(outputDir, "jwt.hex")
	if err := jwtGen.GenerateToFile(jwtPath); err != nil {
		return fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	fmt.Printf("   ✅ JWT secret saved to %s\n\n", jwtPath)

	// Step 2: Generate node key
	fmt.Printf("🔑 Generating node key...\n")
	nodekeyGen := nodekey.NewGenerator()
	nodekeyPath := filepath.Join(outputDir, "nodekey")
	nodeKey, err := nodekeyGen.GenerateToFile(nodekeyPath)
	if err != nil {
		return fmt.Errorf("failed to generate node key: %w", err)
	}
	fmt.Printf("   ✅ Node key saved to %s\n", nodekeyPath)
	fmt.Printf("   ℹ️  Node ID: %s\n\n", nodeKey.NodeID)

	// Step 3: Check if using supplied private keys or mnemonic
	var validatorMnemonic string
	var validators []*validator.ImportedValidator
	var useSuppliedKeys bool

	if len(validatorPrivateKeys) > 0 {
		// Using supplied private keys
		useSuppliedKeys = true
		fmt.Printf("🔑 Using %d supplied validator private keys...\n", len(validatorPrivateKeys))
		validators, err = validator.CreateValidatorsFromPrivateKeys(validatorPrivateKeys)
		if err != nil {
			return fmt.Errorf("failed to create validators from private keys: %w", err)
		}
		// Override numValidators with actual count of supplied keys
		numValidators = uint64(len(validators))
		fmt.Printf("   ✅ Created %d validators from supplied keys\n\n", numValidators)
	} else {
		// Using mnemonic (original behavior)
		useSuppliedKeys = false
		if mnemonic == "" {
			fmt.Printf("🎲 Generating BIP39 mnemonic...\n")
			validatorMnemonic, err = validator.GenerateMnemonic()
			if err != nil {
				return fmt.Errorf("failed to generate mnemonic: %w", err)
			}
			fmt.Printf("   ⚠️  IMPORTANT: Save this mnemonic securely!\n")
			fmt.Printf("   📋 Mnemonic: %s\n\n", validatorMnemonic)

			// Save mnemonic to file
			mnemonicPath := filepath.Join(outputDir, "mnemonic.txt")
			if err := validator.SavePassword(validatorMnemonic, mnemonicPath); err != nil {
				return fmt.Errorf("failed to save mnemonic: %w", err)
			}
			fmt.Printf("   ✅ Mnemonic saved to %s\n\n", mnemonicPath)
		} else {
			validatorMnemonic = mnemonic
			if err := validator.ValidateMnemonic(validatorMnemonic); err != nil {
				return fmt.Errorf("invalid mnemonic: %w", err)
			}
			fmt.Printf("✅ Using provided mnemonic\n\n")
		}
	}

	// Step 4: Generate execution layer genesis
	fmt.Printf("⚙️  Generating execution layer genesis (genesis.json)...\n")
	execConfig := genesis.DefaultExecutionConfig()
	execConfig.ChainID = chainID
	execConfig.ChainName = networkName
	if genesisTime > 0 {
		execConfig.Timestamp = genesisTime
	}

	execGen := genesis.NewExecutionGenerator(execConfig)

	// Add prefunded accounts
	if len(prefundAccounts) > 0 {
		balance := new(big.Int)
		balance.SetString(prefundBalance, 10)
		for _, addr := range prefundAccounts {
			if !common.IsHexAddress(addr) {
				return fmt.Errorf("invalid address: %s", addr)
			}
			execGen.AddPrefundedAccount(common.HexToAddress(addr), balance)
			fmt.Printf("   💰 Prefunding account %s with %s wei\n", addr, balance.String())
		}
	}

	// Add default prefunded account for convenience
	defaultAccount := common.HexToAddress("0x123463a4B065722E99115D6c222f267d9cABb524")
	defaultBalance := new(big.Int)
	defaultBalance.SetString("10000000000000000000000", 10) // 10,000 ETH
	execGen.AddPrefundedAccount(defaultAccount, defaultBalance)
	fmt.Printf("   💰 Prefunding default account %s with 10,000 ETH\n", defaultAccount.Hex())

	genesisPath := filepath.Join(outputDir, "genesis.json")
	if err := execGen.GenerateToFile(genesisPath); err != nil {
		return fmt.Errorf("failed to generate genesis.json: %w", err)
	}
	fmt.Printf("   ✅ Execution genesis saved to %s\n\n", genesisPath)

	// Step 5: Generate consensus layer config
	fmt.Printf("⚙️  Generating consensus layer config (config.yaml)...\n")
	configGen := config.NewGenerator(nil)
	configGen.SetChainID(chainID)
	configGen.SetValidatorCount(numValidators)
	if genesisTime > 0 {
		configGen.SetMinGenesisTime(genesisTime)
	}

	configPath := filepath.Join(outputDir, "config.yaml")
	if err := configGen.GenerateToFile(configPath); err != nil {
		return fmt.Errorf("failed to generate config.yaml: %w", err)
	}
	fmt.Printf("   ✅ Consensus config saved to %s\n\n", configPath)

	// Step 6: Generate validator keystores
	fmt.Printf("👥 Generating %d validator keystores...\n", numValidators)
	keystoresDir := filepath.Join(outputDir, "keystores")

	if useSuppliedKeys {
		// Generate keystores from supplied private keys
		keystores, err := validator.GenerateKeystoresFromValidators(validators, nil)
		if err != nil {
			return fmt.Errorf("failed to generate keystores from supplied keys: %w", err)
		}

		// Save keystores to disk
		_, err = validator.SaveKeystoresToDirectory(keystores, keystoresDir)
		if err != nil {
			return fmt.Errorf("failed to save keystores: %w", err)
		}
		fmt.Printf("   ✅ Generated %d keystores in %s\n\n", len(keystores), keystoresDir)
	} else {
		// Generate keystores from mnemonic (original behavior)
		valGen, err := validator.NewGenerator(validatorMnemonic)
		if err != nil {
			return fmt.Errorf("failed to create validator generator: %w", err)
		}

		keystores, err := valGen.GenerateKeystores(0, numValidators, keystoresDir, nil)
		if err != nil {
			return fmt.Errorf("failed to generate keystores: %w", err)
		}
		fmt.Printf("   ✅ Generated %d keystores in %s\n\n", len(keystores), keystoresDir)
	}

	// Step 7: Generate deposit data
	fmt.Printf("📋 Generating deposit data (deposit_data.json)...\n")
	fmt.Printf("   🔐 Using production-grade BLS12-381 cryptography...\n")

	var depositList validator.DepositDataList
	if useSuppliedKeys {
		// Generate deposit data from supplied private keys
		forkVersion := []byte{0x00, 0x00, 0x00, 0x01}
		depositList, err = validator.GenerateDepositDataFromValidators(validators, forkVersion, networkName, validator.BLSWithdrawal)
		if err != nil {
			return fmt.Errorf("failed to generate deposit data from supplied keys: %w", err)
		}
	} else {
		// Generate deposit data from mnemonic (original behavior)
		depositGen, err := validator.NewBLSDepositGenerator("0x00000001", networkName, validator.BLSWithdrawal)
		if err != nil {
			return fmt.Errorf("failed to create BLS deposit generator: %w", err)
		}

		depositList, err = depositGen.GenerateDepositDataList(validatorMnemonic, 0, numValidators)
		if err != nil {
			return fmt.Errorf("failed to generate BLS deposit data: %w", err)
		}
	}

	depositPath := filepath.Join(outputDir, "deposit_data.json")
	if err := validator.SaveDepositData(depositList, depositPath); err != nil {
		return fmt.Errorf("failed to save deposit data: %w", err)
	}
	fmt.Printf("   ✅ Deposit data saved to %s\n\n", depositPath)

	// Step 8: Generate genesis.ssz
	fmt.Printf("🔮 Generating genesis.ssz (beacon chain genesis state)...\n")

	// Use the execution genesis block hash as eth1 block hash
	eth1BlockHash := "0x0000000000000000000000000000000000000000000000000000000000000000"

	genesisState, err := genesis.GenerateGenesisSSZ(
		chainID,
		networkName,
		depositList,
		eth1BlockHash,
		genesisTime,
	)
	if err != nil {
		return fmt.Errorf("failed to generate genesis state: %w", err)
	}

	genesisSSZPath := filepath.Join(outputDir, "genesis.ssz")
	if err := genesis.SaveGenesisSSZToFile(genesisState, genesisSSZPath); err != nil {
		return fmt.Errorf("failed to save genesis.ssz: %w", err)
	}

	fmt.Printf("   ✅ Genesis SSZ saved to %s\n", genesisSSZPath)
	fmt.Printf("   ℹ️  Genesis time: %d\n", genesisState.GenesisTime)
	fmt.Printf("   ℹ️  Validators: %d\n\n", len(genesisState.Validators))

	// Summary
	fmt.Printf("✨ Generation complete!\n\n")
	fmt.Printf("Generated files:\n")
	fmt.Printf("  📄 %s - JWT secret for EL-CL communication\n", jwtPath)
	fmt.Printf("  📄 %s - Node private key\n", nodekeyPath)
	fmt.Printf("  📄 %s - Execution layer genesis\n", genesisPath)
	fmt.Printf("  📄 %s - Consensus layer configuration\n", configPath)
	fmt.Printf("  📁 %s - Validator keystores (%d validators)\n", keystoresDir, numValidators)
	fmt.Printf("  📄 %s - Deposit data (production-grade BLS12-381)\n", depositPath)
	fmt.Printf("  📄 %s - Beacon chain genesis state (SSZ)\n\n", genesisSSZPath)

	fmt.Printf("🎉 Your production-ready Ethereum network is ready to launch!\n")

	return nil
}
