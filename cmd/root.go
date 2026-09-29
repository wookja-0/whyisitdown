// Package cmd wires the command line to the diagnostic pipeline.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/output"
	"github.com/wookja-0/whyisitdown/internal/runner"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// Exit codes. WARN deliberately exits 0: an expiring certificate is worth
// printing, not worth failing a pipeline over.
const (
	// ExitOK means every check passed or warned.
	ExitOK = 0
	// ExitFailure means a check failed.
	ExitFailure = 1
	// ExitUsage means the command line or the target was invalid.
	ExitUsage = 2
)

type options struct {
	timeout    time.Duration
	noColor    bool
	jsonOut    bool
	verbose    bool
	noRedirect bool
}

// Execute runs the CLI and returns the process exit code. Arguments and
// streams are passed in rather than read from the process, so the command can
// be exercised end to end in tests.
func Execute(version string, args []string, stdout, stderr io.Writer) int {
	var opts options

	cmd := &cobra.Command{
		Use:   "whyisitdown <target>",
		Short: "Find out why a service is down before opening five terminals",
		Long: "whyisitdown checks DNS, TCP, TLS, the certificate, HTTP and redirects\n" +
			"in order, and reports which layer the request stopped at.",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		Example: "  whyisitdown example.com\n" +
			"  whyisitdown https://api.example.com:8443/health --timeout 3s\n" +
			"  whyisitdown example.com --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			// From here on, failures are diagnostic results rather than
			// misuse, so the usage block would only be noise.
			cmd.SilenceUsage = true
			return run(cmd.Context(), args[0], opts, version, stdout)
		},
		Version: version,
	}
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	flags := cmd.Flags()
	flags.DurationVar(&opts.timeout, "timeout", runner.DefaultTimeout, "per-step timeout")
	flags.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colour")
	flags.BoolVar(&opts.jsonOut, "json", false, "print the report as JSON")
	flags.BoolVarP(&opts.verbose, "verbose", "v", false, "show additional detail for each step")
	flags.BoolVar(&opts.noRedirect, "no-redirect", false, "do not follow redirects")

	// Interrupting the run should cancel the in-flight check rather than kill
	// the process mid-write.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := cmd.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}

	var exit *exitError
	if errors.As(err, &exit) {
		return exit.code
	}
	fmt.Fprintln(stderr, "whyisitdown:", err)
	if errors.Is(err, target.ErrInvalid) {
		return ExitUsage
	}
	// Anything left is a cobra flag or argument error.
	return ExitUsage
}

// colorEnabled decides on colour only for a real terminal; anything else, such
// as a buffer in a test or a pipe, stays plain.
func colorEnabled(w io.Writer, noColor bool) bool {
	f, ok := w.(*os.File)
	return ok && output.ColorEnabled(f, noColor)
}

// exitError carries an exit code without a message, for failures that have
// already been reported in the report itself.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func run(ctx context.Context, arg string, opts options, version string, stdout io.Writer) error {
	t, err := target.Parse(arg)
	if err != nil {
		return err
	}
	if opts.timeout <= 0 {
		return fmt.Errorf("%w: --timeout must be positive", target.ErrInvalid)
	}

	report := runner.Run(ctx, t, runner.Options{
		Timeout:         opts.timeout,
		FollowRedirects: !opts.noRedirect,
		UserAgent:       "whyisitdown/" + version,
		Version:         version,
	})

	if opts.jsonOut {
		err = output.JSON(stdout, report)
	} else {
		err = output.Text(stdout, report, output.TextOptions{
			Color:   colorEnabled(stdout, opts.noColor),
			Verbose: opts.verbose,
		})
	}
	if err != nil {
		return err
	}

	if report.Status == check.StatusFail {
		return &exitError{code: ExitFailure}
	}
	return nil
}
