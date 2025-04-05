package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Horiodino/key-length/cmd/display"
	"github.com/Horiodino/key-length/internal/config"
	"github.com/Horiodino/key-length/internal/eval"
	"github.com/Horiodino/key-length/internal/parse"
	"github.com/Horiodino/key-length/internal/types"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keylength-check",
	Short: "A tool to evaluate the security of cryptographic keys and certificates",
	Long:  `keylength-check scans key files or certificates and evaluates their length against security standards.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan a key or certificate file for security evaluation",
	Long:  `Scan evaluates the cryptographic strength of a key or certificate file based on its length and a selected standard.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file := args[0]
		standard, _ := cmd.Flags().GetString("standard")
		checkExpiry, _ := cmd.Flags().GetBool("check-expiry")

		s := display.NewSpinner("Loading configuration")
		cfg, err := config.NewConfig("data/standards.json", standard)
		if err != nil {
			display.StopSpinner(s, false)
			display.PrintError(fmt.Sprintf("Error loading config: %v", err))
			os.Exit(1)
		}
		display.StopSpinner(s, true)

		s = display.NewSpinner("Reading and parsing file")
		data, err := os.ReadFile(file)
		if err != nil {
			display.StopSpinner(s, false)
			display.PrintError(fmt.Sprintf("Error reading file '%s': %v", file, err))
			os.Exit(1)
		}

		parsedKey, err := parse.ParseData(data)
		if err != nil {
			display.StopSpinner(s, false)
			display.PrintError(fmt.Sprintf("Error parsing file '%s': %v", file, err))
			return
		}
		display.StopSpinner(s, true)

		display.PrintSection("Analysis Results", "")
		display.PrintInfo(
			display.FormatKeyValue("File", display.RenderMarkdown(fmt.Sprintf("`%s`", file))),
			display.FormatKeyValue("Standard", display.RenderMarkdown(fmt.Sprintf("`%s`", standard))),
		)
		fmt.Println()

		var certData []byte
		if checkExpiry {
			certData = data
		}
		result := eval.EvaluateKey(parsedKey.Key.(types.KeyLengthEvaluator), cfg, certData)

		if result == nil {
			display.PrintError("Evaluation failed: Result was nil.")
			return
		}

		t := display.CreateTable()
		t.AppendHeader(table.Row{"Property", "Value", "Status"})

		t.AppendRow(table.Row{
			"Algorithm",
			result.Algorithm,
			display.FormatStatus(result.Status),
		})

		t.AppendRow(table.Row{
			"Key Length",
			fmt.Sprintf("%d bits", result.Length),
			display.FormatStatus(result.Status),
		})

		expiryStatus := result.Status
		if checkExpiry && result.Expiry != "" {
			if result.ExpiryWarning != "" {
				expiryStatus = result.ExpiryWarning
			}
			t.AppendRow(table.Row{
				"Expiry",
				result.Expiry,
				display.FormatStatus(expiryStatus),
			})
		}

		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, AutoMerge: true, WidthMax: 20},
			{Number: 2, WidthMax: 30},
			{Number: 3, WidthMax: 30},
		})

		t.Render()

		if checkExpiry && result.Expiry != "" {
			display.PrintCertificateDetails(result.Status, result.Expiry, result.ExpiryWarning)
		}
	},
}

var tlsCmd = &cobra.Command{
	Use:   "tls [host]",
	Short: "Evaluate the TLS certificate of a remote server",
	Long:  `TLS connects to a remote server and evaluates its certificate security.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		standard, _ := cmd.Flags().GetString("standard")
		portsStr, _ := cmd.Flags().GetString("ports")
		checkExpiry, _ := cmd.Flags().GetBool("check-expiry")
		timeoutStr, _ := cmd.Flags().GetString("timeout")

		input = strings.TrimPrefix(input, "https://")
		input = strings.TrimPrefix(input, "http://")
		if strings.Contains(input, "/") {
			input = strings.Split(input, "/")[0]
		}

		ports := []string{"443"}
		if portsStr != "" {
			ports = []string{}
			for _, p := range strings.Split(portsStr, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					ports = append(ports, p)
				}
			}
		}
		if len(ports) == 0 {
			display.PrintError("No valid ports specified.")
			os.Exit(1)
		}

		timeout := 5 * time.Second
		if timeoutStr != "" {
			dur, err := time.ParseDuration(timeoutStr)
			if err != nil {
				display.PrintError(fmt.Sprintf("Invalid timeout format '%s': %v. Using default 5s.", timeoutStr, err))
			} else {
				timeout = dur
			}
		}

		display.PrintSection("TLS Analysis", "")
		display.PrintInfo(
			display.FormatKeyValue("Host", display.RenderMarkdown(fmt.Sprintf("`%s`", input))),
			display.FormatKeyValue("Ports", display.RenderMarkdown(fmt.Sprintf("`%s`", strings.Join(ports, ", ")))),
			display.FormatKeyValue("Timeout", display.RenderMarkdown(fmt.Sprintf("`%s`", timeout))),
			display.FormatKeyValue("Standard", display.RenderMarkdown(fmt.Sprintf("`%s`", standard))),
		)
		fmt.Println()

		cfg, err := config.NewConfig("data/standards.json", standard)
		if err != nil {
			display.PrintError(fmt.Sprintf("Config error: %v", err))
			os.Exit(1)
		}

		t := display.CreateTable()
		t.AppendHeader(table.Row{"Port", "Status", "Algorithm", "Key Length", "Details"})

		secureCount := 0
		totalResults := 0

		spinnerActive := false
		var s spinner.Model
		if len(ports) > 1 {
			s = display.NewSpinner(fmt.Sprintf("Checking %d ports", len(ports)))
			spinnerActive = true
		} else if len(ports) == 1 {
			fmt.Printf("[%s] Checking %s:%s...\n", display.InfoSymbol, input, ports[0])
		}

		for _, port := range ports {
			hostPort := net.JoinHostPort(input, port)

			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: timeout},
				"tcp",
				hostPort,
				&tls.Config{
					ServerName:         input,
					InsecureSkipVerify: true,
				},
			)

			row := table.Row{port, "", "", "", ""}

			if err != nil {
				row[1] = display.FormatStatus("Connection Failed")
				row[4] = fmt.Sprintf("Error: %v", err)
			} else {
				if len(conn.ConnectionState().PeerCertificates) == 0 {
					row[1] = display.FormatStatus("No Certificate")
					row[4] = "Server did not present a certificate."
				} else {
					cert := conn.ConnectionState().PeerCertificates[0]
					parsedKey, pErr := parse.ParseData(cert.Raw)

					if pErr != nil {
						row[1] = display.FormatStatus("Parsing Failed")
						row[4] = fmt.Sprintf("Cert parse error: %v", pErr)
					} else {
						var certData []byte
						if checkExpiry {
							certData = cert.Raw
						}
						result := eval.EvaluateKey(parsedKey.Key.(types.KeyLengthEvaluator), cfg, certData)

						row[1] = display.FormatStatus(result.Status)
						row[2] = result.Algorithm
						row[3] = fmt.Sprintf("%d bits", result.Length)

						details := []string{}
						if checkExpiry {
							expiryDetail := fmt.Sprintf("Expires: %s", result.Expiry)
							if result.ExpiryWarning != "" {
								expiryDetail += fmt.Sprintf(" (%s)", display.FormatStatus(result.ExpiryWarning))
							}
							details = append(details, expiryDetail)
						}
						row[4] = strings.Join(details, "; ")
						if row[4] == "" {
							row[4] = "-"
						}

						if strings.Contains(result.Status, "Secure") {
							secureCount++
						}
						totalResults++
					}
				}
				conn.Close()
			}
			t.AppendRow(row)
		}

		if spinnerActive {
			display.StopSpinner(s, true)
		}

		t.SetColumnConfigs([]table.ColumnConfig{
			{Number: 1, WidthMax: 8},
			{Number: 2, WidthMax: 25},
			{Number: 3, WidthMax: 15},
			{Number: 4, WidthMax: 12},
			{Number: 5, WidthMax: 45},
		})

		if totalResults > 0 || len(ports) > totalResults {
			t.Render()
			display.PrintScanSummary(input, len(ports), secureCount)
		} else if len(ports) == 1 && totalResults == 0 {
		} else if len(ports) > 1 && totalResults == 0 {
			display.PrintError("No TLS connections could be successfully evaluated.")
		}

	},
}

func init() {
	scanCmd.Flags().StringP("standard", "s", "NIST", "Security standard (e.g., NIST, BSI)")
	scanCmd.Flags().BoolP("check-expiry", "e", false, "Check certificate expiry date")
	rootCmd.AddCommand(scanCmd)

	tlsCmd.Flags().StringP("standard", "s", "NIST", "Security standard (e.g., NIST, BSI)")
	tlsCmd.Flags().StringP("ports", "p", "443", "Comma-separated ports (e.g., 443,8443)")
	tlsCmd.Flags().BoolP("check-expiry", "e", false, "Check certificate expiry date")
	tlsCmd.Flags().StringP("timeout", "t", "5s", "Connection timeout (e.g., 3s, 10s)")
	rootCmd.AddCommand(tlsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
