package main

import (
	"fmt"
	"os"

	"github.com/Horiodino/key-length/internal/config"
	"github.com/Horiodino/key-length/internal/eval"
	"github.com/Horiodino/key-length/internal/parse"
	"github.com/Horiodino/key-length/internal/types"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keylength-check",
	Short: "A tool to evaluate the security of cryptographic keys and certificates",
	Long:  `keylength-check scans key files or certificates and evaluates their length against security standards.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan a key or certificate file for security evaluation",
	Long:  `Scan evaluates the cryptographic strength of a key or certificate file based on its length and a selected standard.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]
		standard, _ := cmd.Flags().GetString("standard")

		cfg, err := config.NewConfig("data/standards.json", standard)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		parsedKey, err := parse.ParseFile(file)
		if err != nil {
			fmt.Printf("Error parsing file %s: %v\n", file, err)
			os.Exit(1)
		}

		result := eval.EvaluateKey(parsedKey.Key.(types.KeyLengthEvaluator), cfg)
		fmt.Printf("Algorithm: %s\nLength: %d bits\nStatus: %s\n", result.Algorithm, result.Length, result.Status)
	},
}

func init() {
	scanCmd.Flags().StringP("standard", "s", "NIST", "Standard to evaluate against (NIST, IETF, BSI)")
	rootCmd.AddCommand(scanCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
