// manifest-go-deps emits deterministic JSON: in-repo Go file dependency edges
// from go list (package resolution, Standard flag) and go/parser (imports).
package main

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type result struct {
	ModulePath       string              `json:"module_path"`
	RepoRoot         string              `json:"repo_root"`
	FileOutgoingRepo map[string][]string `json:"file_outgoing_repo"`
	FileIncomingRepo map[string][]string `json:"file_incoming_repo"`
	FileStdlib       map[string][]string `json:"file_go_stdlib_imports"`
	FileExternal     map[string][]string `json:"file_go_external_imports"`
	Errors           []string            `json:"errors"`
}

type pkgInfo struct {
	Standard bool
	InRepo   []string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	if err := os.Chdir(root); err != nil {
		emit(result{Errors: []string{"chdir: " + err.Error()}})
		return
	}
	absRoot, err := filepath.Abs(".")
	if err != nil {
		emit(result{Errors: []string{"abs: " + err.Error()}})
		return
	}

	raw, err := exec.Command("go", "list", "-json", "-deps", "./...").Output()
	if err != nil {
		emit(result{Errors: []string{"go list: " + err.Error()}})
		return
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	modulePath := ""
	pkgs := make(map[string]pkgInfo)

	for dec.More() {
		var p struct {
			ImportPath string `json:"ImportPath"`
			Dir        string `json:"Dir"`
			Standard   bool   `json:"Standard"`
			Module     *struct {
				Path string `json:"Path"`
				Main bool   `json:"Main"`
			} `json:"Module"`
			GoFiles        []string `json:"GoFiles"`
			CgoFiles       []string `json:"CgoFiles"`
			IgnoredGoFiles []string `json:"IgnoredGoFiles"`
		}
		if err := dec.Decode(&p); err != nil {
			emit(result{Errors: []string{"json decode: " + err.Error()}})
			return
		}
		if p.Module != nil && p.Module.Main && p.Module.Path != "" {
			modulePath = p.Module.Path
		}
		if p.ImportPath == "" || p.Dir == "" {
			continue
		}
		var inRepo []string
		for _, n := range append(append(append([]string{}, p.GoFiles...), p.CgoFiles...), p.IgnoredGoFiles...) {
			abs := filepath.Join(p.Dir, n)
			rel, err := filepath.Rel(absRoot, abs)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			inRepo = append(inRepo, filepath.ToSlash(rel))
		}
		sort.Strings(inRepo)
		inRepo = uniqSorted(inRepo)
		prev := pkgs[p.ImportPath]
		pkgs[p.ImportPath] = pkgInfo{
			Standard: p.Standard || prev.Standard,
			InRepo:   inRepo,
		}
	}

	if modulePath == "" {
		modulePath = "ransomeye"
	}

	var moduleFiles []string
	for ip, inf := range pkgs {
		if ip == modulePath || strings.HasPrefix(ip, modulePath+"/") {
			moduleFiles = append(moduleFiles, inf.InRepo...)
		}
	}
	sort.Strings(moduleFiles)
	moduleFiles = uniqSorted(moduleFiles)

	outgoing := make(map[string]map[string]struct{})
	incoming := make(map[string]map[string]struct{})
	stdlib := make(map[string][]string)
	external := make(map[string][]string)

	add := func(from, to string) {
		if from == to {
			return
		}
		if outgoing[from] == nil {
			outgoing[from] = make(map[string]struct{})
		}
		outgoing[from][to] = struct{}{}
		if incoming[to] == nil {
			incoming[to] = make(map[string]struct{})
		}
		incoming[to][from] = struct{}{}
	}

	for _, rel := range moduleFiles {
		abs := filepath.Join(absRoot, rel)
		b, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		pf, err := parser.ParseFile(fset, abs, b, parser.ImportsOnly)
		if err != nil {
			continue
		}
		var st, ex []string
		for _, im := range pf.Imports {
			path := strings.Trim(im.Path.Value, `"`)
			if path == "" {
				continue
			}
			inf, ok := pkgs[path]
			if !ok || len(inf.InRepo) == 0 {
				if ok && inf.Standard {
					st = append(st, path)
					continue
				}
				ex = append(ex, path)
				continue
			}
			for _, t := range inf.InRepo {
				add(rel, t)
			}
		}
		if len(st) > 0 {
			sort.Strings(st)
			stdlib[rel] = uniqSorted(st)
		}
		if len(ex) > 0 {
			sort.Strings(ex)
			external[rel] = uniqSorted(ex)
		}
	}

	// Intra-package ring: imports resolve only across packages; connect files within each package.
	for ip, inf := range pkgs {
		if ip != modulePath && !strings.HasPrefix(ip, modulePath+"/") {
			continue
		}
		fs := append([]string{}, inf.InRepo...)
		if len(fs) < 2 {
			continue
		}
		sort.Strings(fs)
		for i := range fs {
			add(fs[i], fs[(i+1)%len(fs)])
		}
	}

	emit(result{
		ModulePath:       modulePath,
		RepoRoot:         filepath.ToSlash(absRoot),
		FileOutgoingRepo: mapStringSetToSorted(outgoing),
		FileIncomingRepo: mapStringSetToSorted(incoming),
		FileStdlib:       stdlib,
		FileExternal:     external,
		Errors:           nil,
	})
}

func emit(r result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r)
}

func uniqSorted(s []string) []string {
	seen := make(map[string]struct{})
	var o []string
	for _, x := range s {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		o = append(o, x)
	}
	sort.Strings(o)
	return o
}

func mapStringSetToSorted(m map[string]map[string]struct{}) map[string][]string {
	out := make(map[string][]string)
	for k, set := range m {
		var xs []string
		for x := range set {
			xs = append(xs, x)
		}
		sort.Strings(xs)
		out[k] = xs
	}
	return out
}
