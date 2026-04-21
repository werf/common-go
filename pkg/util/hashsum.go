package util

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spaolacci/murmur3"
	"golang.org/x/crypto/sha3"
	"golang.org/x/mod/sumdb/dirhash"
)

// LegacyMurmurHash function returns a hash of non-fixed length (1-8 symbols)
func LegacyMurmurHash(args ...string) string {
	h32 := murmur3.New32()
	h32.Write([]byte(prepareHashArgs(args...)))
	sum := h32.Sum32()
	return fmt.Sprintf("%x", sum)

	// TODO: use byte slice instead of uint32
	// bytes := (*[4]byte)(unsafe.Pointer(&sum))
	// return fmt.Sprintf("%x", *bytes)
}

func Sha3_224Hash(args ...string) string {
	sum := sha3.Sum224([]byte(prepareHashArgs(args...)))
	return fmt.Sprintf("%x", sum)
}

func Sha256Hash(args ...string) string {
	sum := sha256.Sum256([]byte(prepareHashArgs(args...)))
	return fmt.Sprintf("%x", sum)
}

// For file: hash contents of file with its name.
// For directory: hash contents of all files in directory, along with their relative filenames.
func HashContentsAndPathsRecurse(path string) (string, error) {
	path = filepath.Clean(path)

	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("unable to stat %q: %w", path, err)
	}

	var hash string
	if fi.IsDir() {
		if hash, err = hashDir(path, "/"); err != nil {
			return "", fmt.Errorf("unable to calculate hash for dir %q: %w", path, err)
		}
	} else {
		if hash, err = dirhash.Hash1([]string{filepath.Base(path)}, func(_ string) (io.ReadCloser, error) {
			return os.Open(path)
		}); err != nil {
			return "", fmt.Errorf("unable to calculate hash for file %q: %w", path, err)
		}
	}

	return hash, nil
}

// hashDir is a symlink-aware replacement for dirhash.HashDir.
//
// dirhash.HashDir crashes on symlinks pointing to directories because
// filepath.Walk (via Lstat) lists them as files, then os.Open follows
// the symlink and opens a directory, causing io.Copy to fail.
//
// All symlinks are hashed by their target path (os.Readlink), matching
// how Docker and buildah handle symlinks during COPY: they preserve
// symlinks as-is without following them. This also handles dangling
// symlinks correctly, since os.Readlink does not require the target
// to exist.
//
// For trees without symlinks, the output is identical to dirhash.HashDir.
func hashDir(dir, prefix string) (string, error) {
	dir = filepath.Clean(dir)

	var files []string
	symlinks := make(map[string]bool)

	err := filepath.Walk(dir, func(file string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if file == dir {
			return fmt.Errorf("%s is not a directory", dir)
		}

		rel := file
		if dir != "." {
			rel = file[len(dir)+1:]
		}
		f := filepath.ToSlash(filepath.Join(prefix, rel))
		files = append(files, f)

		if info.Mode()&os.ModeSymlink != 0 {
			symlinks[f] = true
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	osOpen := func(name string) (io.ReadCloser, error) {
		p := filepath.Join(dir, strings.TrimPrefix(name, prefix))
		if symlinks[name] {
			link, err := os.Readlink(p)
			if err != nil {
				return nil, fmt.Errorf("unable to read symlink %q: %w", p, err)
			}
			return io.NopCloser(strings.NewReader(link)), nil
		}
		return os.Open(p)
	}

	return dirhash.Hash1(files, osOpen)
}

func prepareHashArgs(args ...string) string {
	return strings.Join(args, ":::")
}
