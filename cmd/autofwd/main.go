// Command autofwd mirrors every TCP port that starts listening on a remote
// Linux host onto the same port on local loopback, over one SSH connection.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/guillaume86/autofwd/internal/config"
	"github.com/guillaume86/autofwd/internal/logx"
	"github.com/guillaume86/autofwd/internal/ports"
	"github.com/guillaume86/autofwd/internal/sshconn"
	"github.com/guillaume86/autofwd/internal/supervisor"
	"github.com/guillaume86/autofwd/internal/ui"
)

// version is set by GoReleaser with -ldflags "-X main.version=...". For
// `go install module@version` builds it comes from the module info instead.
var version = ""

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

const usage = `Usage: autofwd [flags] [user@]<host>

Forwards every TCP port listening on <host> to the same port on this
machine's localhost (127.0.0.1 and ::1), adding and removing forwards as
remote services start and stop. <host> is looked up in ~/.ssh/config.

Flags:
`

type options struct {
	interval      time.Duration
	minPort       int
	ignore        string
	only          string
	allUsers      bool
	ignoreProcess patternsFlag
	quiet         bool
	verbose       bool
	plain         bool
	configPath    string
}

// patternsFlag collects a repeatable regexp flag. The first use replaces
// the defaults; an empty value clears the list.
type patternsFlag struct {
	list []string
	set  bool
}

func (p *patternsFlag) String() string { return strings.Join(p.list, " ") }

func (p *patternsFlag) Set(s string) error {
	if !p.set {
		p.list, p.set = nil, true
	}
	if s == "" {
		p.list = nil
		return nil
	}
	if _, err := regexp.Compile(s); err != nil {
		return err
	}
	p.list = append(p.list, s)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// durationFlag is a time.Duration flag that also accepts a bare number of
// seconds, matching the config file.
type durationFlag struct{ d *time.Duration }

func (f durationFlag) String() string {
	if f.d == nil {
		return ""
	}
	return f.d.String()
}

func (f durationFlag) Set(s string) error {
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		*f.d = time.Duration(n * float64(time.Second))
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("want seconds or a duration like 2s or 500ms")
	}
	*f.d = d
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("autofwd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	printUsage := func(w io.Writer) {
		fmt.Fprint(w, usage)
		fs.SetOutput(w)
		fs.PrintDefaults()
		fs.SetOutput(stderr)
		fmt.Fprintf(w, "\nFlags may also follow the host. Config file (optional): %s\n", config.DefaultPath())
	}
	fs.Usage = func() {} // printed by hand below: stdout for --help, nothing on errors
	usageError := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "autofwd: "+format+"\n", a...)
		fmt.Fprintln(stderr, "Run 'autofwd --help' for usage.")
		return 2
	}
	var o options
	o.interval = 2 * time.Second
	o.ignoreProcess.list = slices.Clone(ports.DefaultIgnoreProcess)
	fs.Var(durationFlag{&o.interval}, "interval", "how often to poll the remote port table, in seconds or as a `duration` like 500ms")
	fs.IntVar(&o.minPort, "min-port", 1024, "ignore remote ports below this")
	fs.StringVar(&o.ignore, "ignore", "", "ports never to forward, e.g. 5432,6379,40000-50000")
	fs.StringVar(&o.only, "only", "", "forward only these ports (overrides every other filter)")
	fs.BoolVar(&o.allUsers, "all-users", false, "also forward ports owned by other users (by default only Docker-style proxies are)")
	fs.Var(&o.ignoreProcess, "ignore-process", "skip remote processes whose name, command line or systemd unit matches this `regexp`; repeatable, replaces the defaults, empty clears them")
	fs.BoolVar(&o.quiet, "quiet", false, "log only warnings and errors")
	fs.BoolVar(&o.quiet, "q", false, "shorthand for --quiet")
	fs.BoolVar(&o.verbose, "verbose", false, "log connections and diagnostics too")
	fs.BoolVar(&o.verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&o.plain, "log", false, "plain log output: no colors, keys or status footer (automatic when not on a terminal)")
	fs.StringVar(&o.configPath, "config", "", "config file `path` (default "+config.DefaultPath()+")")
	showVersion := fs.Bool("version", false, "print the version and exit")

	// Accept flags after the host too: autofwd devbox -v.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				printUsage(stdout)
				return 0
			}
			fmt.Fprintln(stderr, "Run 'autofwd --help' for usage.")
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if *showVersion {
		fmt.Fprintln(stdout, "autofwd", versionString())
		return 0
	}
	switch {
	case len(positional) == 0:
		return usageError("missing host argument")
	case len(positional) > 1:
		return usageError("unexpected argument %q (one host only)", positional[1])
	}
	dest := positional[0]
	alias := dest
	if _, a, ok := strings.Cut(dest, "@"); ok {
		alias = a
	}
	if alias == "" || strings.ContainsAny(alias, " \t") {
		return usageError("invalid host %q", dest)
	}

	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := applyConfig(&o, set, alias); err != nil {
		return usageError("config file: %v", err)
	}
	if o.quiet && o.verbose {
		return usageError("--quiet and --verbose are mutually exclusive")
	}
	if o.interval < 100*time.Millisecond {
		return usageError("--interval must be at least 100ms")
	}
	if o.minPort < 0 || o.minPort > 65535 {
		return usageError("--min-port must be between 0 and 65535")
	}
	filter := ports.Filter{MinPort: uint16(o.minPort), AllUsers: o.allUsers}
	var err error
	if filter.Ignore, err = ports.ParseSet(o.ignore); err != nil {
		return usageError("--ignore: %v", err)
	}
	if filter.Only, err = ports.ParseSet(o.only); err != nil {
		return usageError("--only: %v", err)
	}
	for _, p := range o.ignoreProcess.list {
		re, err := regexp.Compile(p)
		if err != nil {
			return usageError("--ignore-process: %v", err)
		}
		filter.IgnoreProcess = append(filter.IgnoreProcess, re)
	}

	level := logx.Normal
	switch {
	case o.quiet:
		level = logx.Quiet
	case o.verbose:
		level = logx.Verbose
	}
	// Interactive mode (colors, keys, the status footer) needs a terminal on
	// both stderr and stdin; otherwise, or with --log, this is a plain log.
	term := ui.New(stderr, ui.Options{Plain: o.plain})
	defer term.Close()
	var input *ui.Input
	if term.Interactive() {
		input = ui.OpenInput(os.Stdin)
		defer input.Close()
	}
	log := logx.New(term, level)
	prompt := ui.Prompter{Term: term, Input: input}

	resolver, err := sshconn.NewResolver()
	if err != nil {
		fmt.Fprintln(stderr, "autofwd:", err)
		return 1
	}
	dialer := sshconn.NewDialer(resolver, prompt.Prompt, log)
	h, err := dialer.Resolve(dest)
	if err != nil {
		fmt.Fprintln(stderr, "autofwd:", err)
		return 1
	}
	via := ""
	if h.ProxyJump != "" {
		via = " via " + h.ProxyJump
	}
	log.Debugf("  %s is %s@%s:%s%s; filter: min-port %d, ignore %q, only %q, all-users %v, ignore-process %q",
		alias, h.User, h.HostName, h.Port, via, filter.MinPort, filter.Ignore, filter.Only, filter.AllUsers, o.ignoreProcess.list)

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()
	go func() {
		<-sigCtx.Done()
		stop() // a second Ctrl+C kills the process outright
	}()

	sup := supervisor.New(supervisor.Options{
		Dest:     dest,
		Dial:     supervisor.DialFunc(dialer, dest),
		Filter:   filter,
		Interval: o.interval,
		Log:      log,
	})
	runKeys(ctx, cancel, term, input, sup, log)
	if err := sup.Run(ctx); err != nil {
		term.Close()
		fmt.Fprintln(stderr, "autofwd:", err)
		return 1
	}
	return 0
}

// applyConfig fills every option the command line did not set from the
// config file.
func applyConfig(o *options, set map[string]bool, alias string) error {
	path, required := o.configPath, true
	if path == "" {
		path, required = config.DefaultPath(), false
	}
	if path == "" {
		return nil
	}
	f, err := config.Load(path, required)
	if err != nil {
		return err
	}
	s := f.For(alias)
	if s.Interval != nil && !set["interval"] {
		o.interval = s.Interval.Duration
	}
	if s.MinPort != nil && !set["min-port"] {
		o.minPort = *s.MinPort
	}
	if s.Ignore != nil && !set["ignore"] {
		o.ignore = s.Ignore.Spec
	}
	if s.Only != nil && !set["only"] {
		o.only = s.Only.Spec
	}
	if s.AllUsers != nil && !set["all-users"] {
		o.allUsers = *s.AllUsers
	}
	if s.IgnoreProcess != nil && !set["ignore-process"] {
		o.ignoreProcess.list = s.IgnoreProcess.Patterns
	}
	// --quiet and --verbose on the command line override either setting
	// from the file, so `-v` works even with quiet = true configured.
	cliLevel := set["quiet"] || set["q"] || set["verbose"] || set["v"]
	if s.Quiet != nil && !cliLevel {
		o.quiet = *s.Quiet
	}
	if s.Verbose != nil && !cliLevel {
		o.verbose = *s.Verbose
	}
	return nil
}
