package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

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

var tlsCmd = &cobra.Command{
	Use:   "tls [host]",
	Short: "Evaluate the TLS certificate of a remote server",
	Long:  `TLS connects to a remote server (e.g., example.com or example.com:443) and evaluates the security of its certificate based on the selected standard.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		standard, _ := cmd.Flags().GetString("standard")

		input = strings.TrimPrefix(input, "https://")
		input = strings.TrimPrefix(input, "http://")

		hostPort := input
		if !strings.Contains(input, ":") {
			hostPort = input + ":443"
		}

		parts := strings.Split(hostPort, ":")
		if len(parts) != 2 {
			fmt.Println("Error: invalid host format; use host or host:port (e.g., example.com or example.com:443)")
			os.Exit(1)
		}
		host := parts[0]

		cfg, err := config.NewConfig("data/standards.json", standard)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		conn, err := tls.Dial("tcp", hostPort, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err != nil {
			fmt.Printf("Error connecting to %s: %v\n", hostPort, err)
			os.Exit(1)
		}
		defer conn.Close()

		if len(conn.ConnectionState().PeerCertificates) == 0 {
			fmt.Println("Error: no certificates found")
			os.Exit(1)
		}
		cert := conn.ConnectionState().PeerCertificates[0]

		parsedKey, err := parse.ParseData(cert.Raw)
		if err != nil {
			fmt.Printf("Error parsing certificate from %s: %v\n", hostPort, err)
			os.Exit(1)
		}

		result := eval.EvaluateKey(parsedKey.Key.(types.KeyLengthEvaluator), cfg)
		fmt.Printf("Algorithm: %s\nLength: %d bits\nStatus: %s\n", result.Algorithm, result.Length, result.Status)
	},
}

func init() {
	scanCmd.Flags().StringP("standard", "s", "NIST", "Standard to evaluate against (NIST, IETF, BSI)")
	rootCmd.AddCommand(scanCmd)

	tlsCmd.Flags().StringP("standard", "s", "NIST", "Standard to evaluate against (NIST, IETF, BSI)")
	rootCmd.AddCommand(tlsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
