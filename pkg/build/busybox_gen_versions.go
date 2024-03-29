//go:build ignore

package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

const (
	busyboxGit = "git://busybox.net/busybox.git"
)

var (
	semverDashRegex = regexp.MustCompile(`^v?(\d+[\._]\d+[\._]\d+)$`)
	appletLineRegex = regexp.MustCompile(`^//applet:(.*)APPLET(_\w+)?\(\s*([^\s]+)\s*,\s*(\w+\s*,)?\s*BB_DIR_(\w+),`)
	cFilesRegex     = regexp.MustCompile(`\.c$`)
)
var versionsTemplate = template.Must(template.New("versions").Parse(`// Code generated by go generate; DO NOT EDIT.
// This file was generated by go:generate at
// {{ .Timestamp }}
//
// DO NOT EDIT!
//
// To regenerate, run
//
//   go generate
//
package {{ .Package }}

func init() {
	busyboxLinks = map[string][]string{
{{- range $version, $applets := .Applets }}
        "{{$version}}": {
                {{- range $applet := $applets }}
                "{{$applet}}",
                {{- end }}
        },
{{- end }}
}
busyboxLinks["default"] = busyboxLinks["{{ .Default }}"]
}
`))

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: %s <target-package> <base-version> <outfile, or - for stdout>", os.Args[0])
	}
	targetPackage := os.Args[1]
	baseVersion := os.Args[2]
	outfile := os.Args[3]
	var w io.Writer
	if outfile == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(outfile)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		defer f.Close()
		w = f
	}
	applets, err := getBusyboxApplets(baseVersion)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	var versions []string
	for version := range applets {
		versions = append(versions, version)
	}
	versionsTemplate.Execute(w, struct {
		Timestamp time.Time
		Package   string
		Applets   map[string][]string
		Default   string
	}{
		Timestamp: time.Now(),
		Package:   targetPackage,
		Applets:   applets,
		Default:   highestVersion(versions),
	})
}

func getBusyboxApplets(baseVersion string) (map[string][]string, error) {
	// clone the repository
	dir, err := os.MkdirTemp("", "clone-example")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir) // clean up

	// Clones the repository into the given dir, just as a normal git clone does
	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL: busyboxGit,
	})
	if err != nil {
		return nil, err
	}

	// get the tags
	versions, err := getBusyboxVersions(repo, baseVersion)

	// get the applets for each version
	applets := make(map[string][]string)
	for _, version := range versions {
		cleanVersion := strings.ReplaceAll(version, "_", ".")
		applets[cleanVersion], err = getBusyboxAppletsForVersion(repo, version)
		if err != nil {
			return nil, err
		}
	}
	return applets, nil
}

func getBusyboxVersions(repo *git.Repository, minVersion string) (versions []string, err error) {
	// now get the tags
	tags, err := repo.Tags()
	if err != nil {
		return nil, err
	}
	// iterate over the tags
	// we only want those that match semver, and are higher than our base version
	err = tags.ForEach(func(tag *plumbing.Reference) error {
		tagName := tag.Name().Short()
		matches := semverDashRegex.FindAllStringSubmatch(tagName, -1)
		if len(matches) < 1 || len(matches[0]) < 2 {
			return nil
		}
		// get to proper . over _
		version := strings.ReplaceAll(matches[0][1], "_", ".")
		if semverLess(version, minVersion) {
			return nil
		}
		versions = append(versions, tagName)
		return nil
	})

	return
}

func getBusyboxAppletsForVersion(repo *git.Repository, version string) (applets []string, err error) {
	// checkout the tag
	tree, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	err = tree.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName("refs/tags/" + version),
	})
	if err != nil {
		return nil, err
	}

	// find the applets
	entries, err := tree.Grep(&git.GrepOptions{
		Patterns:  []*regexp.Regexp{appletLineRegex},
		PathSpecs: []*regexp.Regexp{cFilesRegex},
	})
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		line := appletLineToFullPath(entry.Content)
		if line != "" {
			applets = append(applets, line)
		}
	}
	sort.Strings(applets)
	return
}

func semverLess(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aI, _ := strconv.ParseInt(aParts[i], 10, 64)
		bI, _ := strconv.ParseInt(bParts[i], 10, 64)
		if aI < bI {
			return true
		}
		if aI > bI {
			return false
		}
	}
	return false
}

func appletLineToFullPath(appletLine string) string {
	// the line should look something like one of these two:
	// //applet:IF_<something>(APPLET(name, location, ... <other stuff we do not care about for now>))
	// //applet:IF_<something>(APPLET_<something>(name, maincall, location, ... <other stuff we do not care about for now>))
	//
	// location will be BB_DIR_<path> where everything in <path> can be lower-cased and _ converted to /
	// e.g. BB_DIR_USR_BIN -> /usr/bin
	// e.g. BB_DIR_USR_SBIN -> /usr/sbin
	// e.g. BB_DIR_BIN -> /sbin
	// etc.
	matches := appletLineRegex.FindAllStringSubmatch(appletLine, -1)
	if len(matches) < 1 || len(matches[0]) < 6 {
		return ""
	}
	return fmt.Sprintf("/%s/%s", strings.ToLower(strings.ReplaceAll(matches[0][5], "_", "/")), matches[0][3])
}

func highestVersion(versions []string) string {
	highest := ""
	for _, version := range versions {
		if semverLess(highest, version) {
			highest = version
		}
	}
	return highest
}
