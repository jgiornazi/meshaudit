package report

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	"github.com/jgiornazi/meshaudit/internal/audit"
	"github.com/jgiornazi/meshaudit/internal/drift"
)

// ANSI color + icon helpers.
var (
	green  = color.New(color.FgGreen, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	bold   = color.New(color.Bold)
	dim    = color.New(color.Faint)
)

const divider = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

// PrintHeader writes the scan header line.
func PrintHeader(w io.Writer, version, cluster, namespace string) {
	dim.Fprintln(w, divider)
	bold.Fprintf(w, "meshaudit %s", version)
	fmt.Fprintf(w, "  |  cluster: %s  |  namespace: %s\n", cluster, namespace)
	dim.Fprintln(w, divider)
}

// PrintMTLS writes the mTLS posture section.
func PrintMTLS(w io.Writer, findings []audit.MTLSFinding) {
	bold.Fprintln(w, "\nmTLS Posture")

	for _, f := range findings {
		icon, label, c := modeStyle(f.Mode)
		fmt.Fprintf(w, "  %s  %-40s %s\n",
			icon,
			dim.Sprint(f.Namespace+"/") + c.Sprint(f.Service),
			c.Sprint(label),
		)
		if f.SuggestedFix != "" {
			fmt.Fprintf(w, "        %s\n", dim.Sprint("→ "+f.SuggestedFix))
		}
	}
}

// PrintAuthz writes the AuthorizationPolicy findings section.
func PrintAuthz(w io.Writer, findings []audit.AuthzFinding) {
	bold.Fprintln(w, "\nAuthorizationPolicy")

	for _, f := range findings {
		icon, c := severityStyle(f.Severity)
		target := f.Policy
		if f.Service != "" {
			target = f.Service
		}
		fmt.Fprintf(w, "  %s  %-40s %s\n",
			icon,
			dim.Sprint(f.Namespace+"/") + c.Sprint(target),
			c.Sprint(f.Detail),
		)
		if f.SuggestedFix != "" {
			fmt.Fprintf(w, "        %s\n", dim.Sprint("→ "+f.SuggestedFix))
		}
	}
}

// PrintSummary writes the final divider, posture score, and pass/warn/fail counts.
// It now accepts both mTLS and authz findings so the score uses the full formula.
func PrintSummary(w io.Writer, mtls []audit.MTLSFinding, authz []audit.AuthzFinding) {
	result := audit.Compute(mtls, authz)
	pass, warn, fail := audit.Summary(mtls, authz)

	fmt.Fprintln(w)
	dim.Fprintln(w, divider)

	c := scoreColor(result.Score)
	c.Fprintf(w, "Security Posture Score: %d / 100 [%s]\n", result.Score, result.Band)
	fmt.Fprintf(w, "%s  %s  %s\n",
		green.Sprintf("✔ %d PASS", pass),
		yellow.Sprintf("⚠ %d WARN", warn),
		red.Sprintf("✖ %d FAIL", fail),
	)

	dim.Fprintln(w, divider)
}

// modeStyle returns the display icon, label text, and color for a given mTLS mode.
func modeStyle(mode audit.MTLSMode) (icon string, label string, c *color.Color) {
	switch mode {
	case audit.ModeStrict:
		return green.Sprint("■"), "strict mTLS", green
	case audit.ModePermissive:
		return yellow.Sprint("■■"), "permissive mTLS — vulnerable to plaintext", yellow
	case audit.ModeDisabled:
		return red.Sprint("■"), "mTLS disabled — high risk", red
	default:
		return dim.Sprint("?"), string(mode), dim
	}
}

// severityStyle returns the icon and color for an authz finding severity.
func severityStyle(sev audit.AuthzSeverity) (icon string, c *color.Color) {
	switch sev {
	case audit.SeverityFail:
		return red.Sprint("■"), red
	case audit.SeverityWarn:
		return yellow.Sprint("■"), yellow
	default: // INFO
		return green.Sprint("■"), green
	}
}

func scoreColor(score int) *color.Color {
	switch {
	case score >= 90:
		return green
	case score >= 70:
		return yellow
	default:
		return red
	}
}

// PrintDrift writes a human-readable drift report for a set of VirtualServices.
func PrintDrift(w io.Writer, results []drift.VSResult) {
	bold.Fprintln(w, "\nVirtualService Drift")

	for _, r := range results {
		icon, label, c := driftStyle(r.Status)
		fmt.Fprintf(w, "  %s  %-40s %s\n",
			icon,
			dim.Sprint(r.Namespace+"/") + c.Sprint(r.Name),
			c.Sprint(label),
		)
		for _, d := range r.Diffs {
			fmt.Fprintf(w, "        %s\n",
				dim.Sprintf("└─ %s: live=%v, desired=%v", d.Field, d.Live, d.Desired),
			)
		}
	}
}

// driftStyle returns the icon, label, and color for a drift status.
func driftStyle(status drift.DriftStatus) (icon string, label string, c *color.Color) {
	switch status {
	case drift.StatusInSync:
		return green.Sprint("■"), "IN SYNC", green
	case drift.StatusDrifted:
		return yellow.Sprint("■■"), "DRIFT DETECTED", yellow
	case drift.StatusLiveOnly:
		return red.Sprint("■"), "LIVE ONLY (not in git)", red
	case drift.StatusManifestOnly:
		return yellow.Sprint("■"), "MANIFEST ONLY (not deployed)", yellow
	default:
		return dim.Sprint("?"), string(status), dim
	}
}

// NamespaceOrAll returns "all" when ns is empty, used by the header.
func NamespaceOrAll(ns string) string {
	if ns == "" {
		return "all"
	}
	return ns
}
