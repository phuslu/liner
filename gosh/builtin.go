package gosh

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"slices"
	"time"

	"mvdan.cc/sh/v3/interp"
)

func goshCallHandler(runner func() *interp.Runner, history *goshHistory, bindings *goshKeyBindingManager) interp.CallHandlerFunc {
	return func(ctx context.Context, args []string) ([]string, error) {
		if len(args) == 0 {
			return args, nil
		}
		switch args[0] {
		case "wget":
			if _, err := exec.LookPath(args[0]); err == nil {
				return args, nil
			}
			hc := interp.HandlerCtx(ctx)
			file, err := goshBuiltinWget(ctx, args[1:], hc.Stdout)
			if err != nil {
				fmt.Fprintln(hc.Stderr, err)
				return []string{"false"}, nil
			}
			fmt.Fprintf(hc.Stdout, "Saved %s\n", file)
			return []string{":"}, nil
		case "history":
			if history == nil {
				return args, nil
			}
			hc := interp.HandlerCtx(ctx)
			entries := history.Entries()
			for idx, entry := range entries {
				fmt.Fprintf(hc.Stdout, "%5d  %s\n", idx+1, entry)
			}
			return []string{":"}, nil
		case "bind":
			if bindings == nil {
				return args, nil
			}
			if err := bindings.handleBind(args[1:]); err != nil {
				hc := interp.HandlerCtx(ctx)
				fmt.Fprintln(hc.Stderr, err)
				return []string{"false"}, nil
			}
			return []string{":"}, nil
		case "kill", "newgrp":
			var r *interp.Runner
			if runner != nil {
				r = runner()
			}
			if r != nil && r.Funcs[args[0]] != nil {
				return args, nil
			}
			hc := interp.HandlerCtx(ctx)
			path, err := interp.LookPathDir(hc.Dir, hc.Env, args[0])
			if err != nil {
				return args, nil
			}
			next := slices.Clone(args)
			next[0] = path
			return next, nil
		default:
			return args, nil
		}
	}
}

func goshBuiltinWget(ctx context.Context, args []string, out io.Writer) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("wget: builtin only supports a single URL argument")
	}
	rawURL := args[0]
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("wget: invalid url %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("wget: unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("wget: missing host in %q", rawURL)
	}
	name := path.Base(parsed.Path)
	if name == "." || name == "/" || name == "" {
		name = "index.html"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("wget: failed to build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("wget: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("wget: bad status: %s", resp.Status)
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("wget: cannot open %s: %w", name, err)
	}
	defer file.Close()
	progress := &goshWgetProgress{out: out, size: resp.ContentLength}
	defer progress.Done()
	reader := io.TeeReader(resp.Body, progress)
	if _, err := io.Copy(file, reader); err != nil {
		return "", fmt.Errorf("wget: failed to save %s: %w", name, err)
	}
	if err := file.Chmod(0o755); err != nil {
		return "", fmt.Errorf("wget: chmod failed for %s: %w", name, err)
	}
	return name, nil
}

type goshWgetProgress struct {
	out   io.Writer
	size  int64
	total int64
	last  time.Time
	done  bool
}

func (p *goshWgetProgress) Write(b []byte) (int, error) {
	if p == nil || p.out == nil {
		return len(b), nil
	}
	p.total += int64(len(b))
	p.print(false)
	return len(b), nil
}

func (p *goshWgetProgress) print(force bool) {
	if p == nil || p.out == nil {
		return
	}
	if !force && time.Since(p.last) < 200*time.Millisecond {
		return
	}
	p.last = time.Now()
	if p.size > 0 {
		percent := p.total * 100 / p.size
		fmt.Fprintf(p.out, "\r%3d%% %s/%s", percent, p.formatSize(p.total), p.formatSize(p.size))
	} else {
		fmt.Fprintf(p.out, "\r%s", p.formatSize(p.total))
	}
}

func (p *goshWgetProgress) Done() {
	if p == nil || p.out == nil || p.done {
		return
	}
	p.print(true)
	fmt.Fprint(p.out, "\n")
	p.done = true
}

func (p *goshWgetProgress) formatSize(v int64) string {
	if v < 1024 {
		return fmt.Sprintf("%dB", v)
	}
	type unit struct {
		name  string
		value float64
	}
	units := []unit{
		{"K", 1024},
		{"M", 1024 * 1024},
		{"G", 1024 * 1024 * 1024},
	}
	val := float64(v)
	for i := len(units) - 1; i >= 0; i-- {
		if val >= units[i].value {
			return fmt.Sprintf("%.1f%s", val/units[i].value, units[i].name)
		}
	}
	return fmt.Sprintf("%.1fK", val/1024)
}
