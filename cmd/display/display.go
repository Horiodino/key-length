package display

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

var (
	boldStyle = lipgloss.NewStyle().Bold(true)

	SuccessSymbol = "✓"
	WarningSymbol = "!"
	ErrorSymbol   = "✗"
	InfoSymbol    = ">"
)

func PrintLogo() {}

func PrintSection(title string, _ string) {
	fmt.Printf("\n--- %s ---\n", strings.ToUpper(title))
}

func NewSpinner(text string) spinner.Model {
	s := spinner.New()
	s.Spinner = spinner.Line
	fmt.Printf("%s %s... ", s.View(), text)
	return s
}

func StopSpinner(s spinner.Model, success bool) {
	finalMsg := "Done."
	finalSymbol := SuccessSymbol
	if !success {
		finalMsg = "Failed."
		finalSymbol = ErrorSymbol
	}
	fmt.Printf("\r%s %s          \n", finalSymbol, finalMsg)
}

func FormatStatus(status string) string {
	status = strings.TrimSpace(status)
	lowerStatus := strings.ToLower(status)

	symbol := InfoSymbol

	switch {
	case strings.Contains(lowerStatus, "secure"):
		symbol = SuccessSymbol
	case strings.Contains(lowerStatus, "insecure"):
		symbol = ErrorSymbol
	case strings.Contains(lowerStatus, "warning"):
		symbol = WarningSymbol
	case strings.Contains(lowerStatus, "failed"):
		symbol = ErrorSymbol
	}

	return fmt.Sprintf("[%s] %s", symbol, status)
}

func PrintError(msg string) {
	fmt.Printf("[%s] Error: %s\n", ErrorSymbol, msg)
}

func PrintInfo(lines ...string) {
	for _, line := range lines {
		fmt.Printf("  %s\n", line)
	}
}

func FormatKeyValue(key, value string) string {
	return fmt.Sprintf("%s: %s", key, boldStyle.Render(value))
}

func PrintCertificateDetails(status, expiry, expiryWarning string) {
	fmt.Println("\nCertificate Details:")
	PrintInfo(
		FormatKeyValue("Status", FormatStatus(status)),
		FormatKeyValue("Valid Until", expiry),
	)
	if expiryWarning != "" {
		fmt.Printf("  Warning: %s\n", FormatStatus(expiryWarning))
	}
}

func PrintScanSummary(host string, portsScanned, secureCount int) {
	fmt.Println("\nScan Summary:")
	ratio := fmt.Sprintf("%d/%d", secureCount, portsScanned)
	statusSymbol := SuccessSymbol
	if secureCount < portsScanned {
		statusSymbol = WarningSymbol
	}
	if secureCount == 0 && portsScanned > 0 {
		statusSymbol = ErrorSymbol
	}

	PrintInfo(
		FormatKeyValue("Host", host),
		FormatKeyValue("Ports Scanned", strconv.Itoa(portsScanned)),
		FormatKeyValue("Secure Ports", fmt.Sprintf("[%s] %s", statusSymbol, ratio)),
	)
}

func RenderMarkdown(text string) string {
	r, _ := glamour.NewTermRenderer(
		glamour.WithStylesFromJSONBytes([]byte(`{
			"document": { "margin": 0, "style_inactive": true },
			"blockquote": { "style_inactive": true },
			"code": { "bold": true },
			"code_block": { "margin": 0, "style_inactive": true },
			"em": { "style_inactive": true },
			"heading": { "style_inactive": true },
			"hr": { "style_inactive": true },
			"html_block": { "style_inactive": true },
			"image": { "style_inactive": true },
			"link": { "style_inactive": true },
			"list": { "margin": 0, "style_inactive": true },
			"paragraph": { "margin": 0, "style_inactive": true },
			"strikethrough": { "style_inactive": true },
			"strong": { "bold": true },
			"table": { "style_inactive": true }
		}`)),
		glamour.WithWordWrap(0),
	)
	out, err := r.Render(text)
	if err != nil {
		return text
	}
	return strings.TrimSpace(out)
}

func CreateTable() table.Writer {
	t := table.NewWriter()
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateColumns = true
	style.Options.SeparateRows = false
	style.Options.SeparateHeader = true
	style.Color.Header = text.Colors{text.Bold}
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "

	t.SetStyle(style)
	t.SetOutputMirror(os.Stdout)
	return t
}
