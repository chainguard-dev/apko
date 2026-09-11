package passwd

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	apkfs "chainguard.dev/apko/pkg/apk/fs"
)

type ShadowEntry struct {
	UserName string
	Password string
	LastChg  string
	Min      string
	Max      string
	Warn     string
	Inact    string
	Expire   string
	Flag     string
}

type ShadowFile struct {
	Entries []ShadowEntry
	fsys    apkfs.FullFS
}

// ReadOrCreateShadowFile parses an /etc/shadow file into a ShadowFile.
// An empty file is created if /etc/shadow is missing.
func ReadOrCreateShadowFile(fsys apkfs.FullFS, filepath string) (ShadowFile, error) {
	sf := ShadowFile{fsys: fsys}

	file, err := fsys.OpenFile(filepath, os.O_RDONLY|os.O_CREATE, 0o640)
	if err != nil {
		return sf, fmt.Errorf("failed to open %s: %w", filepath, err)
	}
	defer file.Close()

	if err := sf.Load(file); err != nil {
		return sf, err
	}
	return sf, nil
}

// Read ShadowFile parses an /etc/shadow file into a ShadowFile.
// If /etc/shadow is missing, returns an error
func ReadShadowFile(fsys fs.FS, filepath string) (ShadowFile, error) {
	sf := ShadowFile{}

	file, err := fsys.Open(filepath)
	if err != nil {
		return sf, fmt.Errorf("failed to opne %s: %w", filepath, err)
	}
	defer file.Close()
	if err := sf.Load(file); err != nil {
		return sf, err
	}
	return sf, nil
}

func (sf *ShadowFile) Load(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		se := ShadowEntry{}

		if err := se.Parse(scanner.Text()); err != nil {
			return fmt.Errorf("unable to parse: %w", err)
		}

		sf.Entries = append(sf.Entries, se)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ubale to parse: %w", err)
	}

	return nil
}

func (sf *ShadowFile) WriteFile(filepath string) error {
	file, err := sf.fsys.Create(filepath)
	if err != nil {
		return fmt.Errorf("unable to open %s for writing: %w", filepath, err)
	}
	defer file.Close()

	return sf.Write(file)
}

// Write writes an /etc/shadow file into an io.writer
func (sf *ShadowFile) Write(w io.Writer) error {
	for _, se := range sf.Entries {
		if err := se.Write(w); err != nil {
			return fmt.Errorf("unable to write shadow entry: %w", err)
		}
	}
	return nil
}

// Parse parses an /etc/shadow line into a ShadowEntry
func (se *ShadowEntry) Parse(line string) error {
	line = strings.TrimSpace(line)

	parts := strings.Split(line, ":")
	if len(parts) != 9 {
		return fmt.Errorf("malformed line, contains %d parts, expecting 9", len(parts))
	}
	se.UserName = parts[0]
	se.Password = parts[1]
	se.Min = parts[3]
	se.Max = parts[4]
	se.Warn = parts[5]
	se.Inact = parts[6]
	se.Expire = parts[7]
	se.Flag = parts[8]

	return nil
}

// Write writes an /etc/shadow line into a io.writer
func (se *ShadowEntry) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%s:%s:%s:%s:%s:%s:%s:%s:%s\n", se.UserName, se.Password, se.LastChg, se.Min, se.Max, se.Warn, se.Inact, se.Expire, se.Flag)
	return err
}
