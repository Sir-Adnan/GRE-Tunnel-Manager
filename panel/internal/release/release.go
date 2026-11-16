// Package release finds, downloads, verifies and unpacks published panel
// packages. It never installs anything; callers decide what to do with the
// verified files.
package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repository is the GitHub project that publishes release packages.
const Repository = "Sir-Adnan/GRE-Tunnel-Manager"

const (
	maxArchive = 256 << 20
	maxSums    = 64 << 10
	maxBinary  = 192 << 20
	maxEngine  = 8 << 20
	maxAPI     = 1 << 20
)

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

// Valid reports whether v is a plain MAJOR.MINOR.PATCH release number.
func Valid(v string) bool { return versionPattern.MatchString(v) }

// Compare orders two valid versions: -1, 0 or 1. Invalid input sorts first.
func Compare(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parts(v string) [3]int {
	var out [3]int
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return [3]int{-1, -1, -1}
	}
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

// Arch maps the running platform to a package architecture.
func Arch() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH, nil
	}
	return "", errors.New("supported architectures: x86_64 and aarch64")
}

// ArchiveName is the published archive for one version and architecture.
func ArchiveName(version, arch string) string {
	return fmt.Sprintf("gtm-panel-v%s-linux-%s.tar.gz", version, arch)
}

// Package is an unpacked, verified release: the executable and the engine.
type Package struct {
	Dir, Binary, Engine string
}

// Client talks to GitHub. Every request is HTTPS, bounded and redirect-safe.
type Client struct {
	HTTP      *http.Client
	Download  string // https://github.com/OWNER/REPO/releases/download
	API       string // https://api.github.com/repos/OWNER/REPO
	UserAgent string
}

// Default returns a client for the public repository.
func Default(userAgent string) Client {
	return Client{
		HTTP: &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) > 5 {
				return errors.New("refused redirect")
			}
			return nil
		}},
		Download:  "https://github.com/" + Repository + "/releases/download",
		API:       "https://api.github.com/repos/" + Repository,
		UserAgent: userAgent,
	}
}

// Latest returns the newest published, non-draft, non-prerelease version.
func (c Client) Latest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, e := c.get(ctx, c.API+"/releases/latest", maxAPI, "application/vnd.github+json")
	if e != nil {
		return "", e
	}
	var info struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if e = json.Unmarshal(body, &info); e != nil {
		return "", errors.New("unexpected release response")
	}
	version := strings.TrimPrefix(info.Tag, "v")
	if info.Draft || info.Prerelease || !Valid(version) {
		return "", errors.New("the latest release has no usable version number")
	}
	return version, nil
}

// Fetch places a verified archive for version into dir and unpacks it.
// With from set, the archive and SHA256SUMS are copied from that local
// directory instead of being downloaded.
func (c Client) Fetch(ctx context.Context, version, arch, from, dir string) (Package, error) {
	if !Valid(version) {
		return Package{}, errors.New("invalid version")
	}
	name := ArchiveName(version, arch)
	for _, file := range []struct {
		name  string
		limit int64
	}{{name, maxArchive}, {"SHA256SUMS", maxSums}} {
		var data []byte
		var e error
		if from != "" {
			data, e = readLimited(filepath.Join(from, file.name), file.limit)
		} else {
			data, e = c.get(ctx, c.Download+"/v"+version+"/"+file.name, file.limit, "")
		}
		if e != nil {
			return Package{}, fmt.Errorf("%s: %w", file.name, e)
		}
		if e = os.WriteFile(filepath.Join(dir, file.name), data, 0600); e != nil {
			return Package{}, e
		}
	}
	if e := Verify(dir, name); e != nil {
		return Package{}, e
	}
	return Unpack(filepath.Join(dir, name), dir)
}

func (c Client) get(ctx context.Context, url string, limit int64, accept string) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil, e
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("download failed: %w", e)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: HTTP %d", res.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response is larger than expected")
	}
	return data, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("not a regular file of the expected size")
	}
	return os.ReadFile(path)
}

// Verify checks dir/member against exactly one SHA256SUMS entry.
func Verify(dir, member string) error {
	sums, e := readLimited(filepath.Join(dir, "SHA256SUMS"), maxSums)
	if e != nil {
		return fmt.Errorf("SHA256SUMS: %w", e)
	}
	var want []byte
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != member {
			continue
		}
		if want != nil {
			return errors.New("SHA256SUMS lists the package more than once")
		}
		if want, e = hex.DecodeString(fields[0]); e != nil || len(want) != sha256.Size {
			return errors.New("SHA256SUMS has a malformed entry")
		}
	}
	if want == nil {
		return errors.New("SHA256SUMS does not list " + member)
	}
	f, e := os.Open(filepath.Join(dir, member))
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return e
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return errors.New("checksum mismatch: the package is damaged or was altered")
	}
	return nil
}

// Unpack extracts only the two fixed top-level members; paths from the
// archive are never used to choose where files land.
func Unpack(archive, dir string) (Package, error) {
	f, e := os.Open(archive)
	if e != nil {
		return Package{}, e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return Package{}, errors.New("package is not a gzip archive")
	}
	defer gz.Close()
	want := map[string]struct {
		limit int64
		mode  os.FileMode
	}{"gtm-panel": {maxBinary, 0755}, "gre.sh": {maxEngine, 0700}}
	seen := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return Package{}, errors.New("package archive is damaged")
		}
		spec, ok := want[h.Name]
		if !ok {
			continue
		}
		if seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size > spec.limit {
			return Package{}, errors.New("package contains an unexpected " + h.Name)
		}
		seen[h.Name] = true
		out, e := os.OpenFile(filepath.Join(dir, h.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, spec.mode)
		if e != nil {
			return Package{}, e
		}
		_, e = io.Copy(out, io.LimitReader(tr, spec.limit))
		if ce := out.Close(); e == nil {
			e = ce
		}
		if e != nil {
			return Package{}, e
		}
	}
	if !seen["gtm-panel"] || !seen["gre.sh"] {
		return Package{}, errors.New("package is missing gtm-panel or gre.sh")
	}
	return Package{Dir: dir, Binary: filepath.Join(dir, "gtm-panel"), Engine: filepath.Join(dir, "gre.sh")}, nil
}

// Local describes an already unpacked package directory (from install.sh).
func Local(dir string) (Package, error) {
	p := Package{Dir: dir, Binary: filepath.Join(dir, "gtm-panel"), Engine: filepath.Join(dir, "gre.sh")}
	for _, name := range []string{p.Binary, p.Engine} {
		info, e := os.Lstat(name)
		if e != nil || !info.Mode().IsRegular() {
			return Package{}, errors.New("package directory needs regular gtm-panel and gre.sh files")
		}
	}
	return p, nil
}
