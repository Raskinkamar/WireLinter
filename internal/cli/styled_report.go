package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

type terminalStyle struct {
	color bool
}

func newTerminalStyle(w io.Writer) terminalStyle {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		return terminalStyle{}
	}

	switch strings.ToLower(strings.TrimSpace(os.Getenv("WIRELINT_COLOR"))) {
	case "always":
		return terminalStyle{color: true}
	case "never":
		return terminalStyle{}
	}

	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return terminalStyle{}
	}

	file, ok := w.(*os.File)
	if !ok {
		return terminalStyle{}
	}
	info, err := file.Stat()
	if err != nil {
		return terminalStyle{}
	}
	return terminalStyle{color: info.Mode()&os.ModeCharDevice != 0}
}

func (s terminalStyle) paint(code, value string) string {
	if !s.color || value == "" {
		return value
	}
	return code + value + ansiReset
}

func (s terminalStyle) bold(value string) string { return s.paint(ansiBold, value) }
func (s terminalStyle) dim(value string) string  { return s.paint(ansiDim, value) }

func (s terminalStyle) status(kind, label string) string {
	switch kind {
	case "pass":
		return s.paint(ansiGreen, label)
	case "fail":
		return s.paint(ansiRed, label)
	case "open":
		return s.paint(ansiYellow, label)
	default:
		return s.paint(ansiCyan, label)
	}
}

func writeStyledTextReport(w io.Writer, report model.Report) {
	style := newTerminalStyle(w)

	fmt.Fprintln(w, style.bold("WIRELINT"))
	meta := report.Provider
	if report.Pack != nil {
		meta = fmt.Sprintf("%s  ·  pack %s  ·  protocol %s", report.Provider, report.Pack.Version, report.Pack.Protocol)
	}
	fmt.Fprintln(w, style.dim(meta))
	fmt.Fprintf(w, "%s  %s\n\n", style.dim("trace"), report.TraceID)

	for _, result := range report.Results {
		label := strings.ToUpper(result.Kind)
		if result.Kind == "fail" && result.Level != "" {
			label += "/" + strings.ToUpper(result.Level)
		}

		prefix := label + " " + result.RuleID
		if result.MessageID != "" {
			prefix += " [" + result.MessageID + "]"
		}

		title := strings.TrimSpace(result.Title)
		if title == "" {
			title = result.RuleID
		}

		statusAndRule := style.status(result.Kind, label) + " " + result.RuleID
		if result.MessageID != "" {
			statusAndRule += " " + style.dim("["+result.MessageID+"]")
		}
		padding := 2
		if len(prefix) < 58 {
			padding = 58 - len(prefix)
		}
		fmt.Fprintf(w, "  %s%s%s\n", statusAndRule, strings.Repeat(" ", padding), title)

		if result.Kind != "pass" {
			fmt.Fprintf(w, "      %s\n", result.Message)
			if result.DocsRef != nil && result.DocsRef.URL != "" {
				fmt.Fprintf(w, "      %s %s\n", style.dim("docs"), result.DocsRef.URL)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, style.dim(strings.Repeat("─", 72)))

	parts := []string{
		style.status("pass", fmt.Sprintf("%d passed", report.Summary.Pass)),
		style.status("fail", fmt.Sprintf("%d failed", report.Summary.Fail)),
		style.status("open", fmt.Sprintf("%d open", report.Summary.Open)),
		style.status("notApplicable", fmt.Sprintf("%d n/a", report.Summary.NotApplicable)),
	}
	if report.Summary.Warnings > 0 {
		parts = append(parts, style.status("open", fmt.Sprintf("%d warnings", report.Summary.Warnings)))
	}
	if report.Summary.Notes > 0 {
		parts = append(parts, style.dim(fmt.Sprintf("%d notes", report.Summary.Notes)))
	}
	fmt.Fprintln(w, strings.Join(parts, "  ·  "))
}
