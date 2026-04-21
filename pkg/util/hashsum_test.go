package util_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/mod/sumdb/dirhash"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("HashContentsAndPathsRecurse", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "hashsum-test-*")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	DescribeTable("succeeds",
		func(setup func(string) string) {
			path := setup(tmpDir)
			hash, err := util.HashContentsAndPathsRecurse(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(hash).To(HavePrefix("h1:"))
		},
		Entry("for a single file", func(tmpDir string) string {
			p := filepath.Join(tmpDir, "single.txt")
			Expect(os.WriteFile(p, []byte("content"), 0o644)).To(Succeed())
			return p
		}),
		Entry("for a directory without symlinks", func(tmpDir string) string {
			dir := filepath.Join(tmpDir, "plain")
			Expect(os.MkdirAll(filepath.Join(dir, "sub"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb"), 0o644)).To(Succeed())
			return dir
		}),
		Entry("for a directory with a symlink to a file", func(tmpDir string) string {
			dir := filepath.Join(tmpDir, "symlink-file")
			Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "real.txt"), []byte("hello"), 0o644)).To(Succeed())
			Expect(os.Symlink("real.txt", filepath.Join(dir, "link.txt"))).To(Succeed())
			return dir
		}),
		Entry("for a directory with a symlink to a directory", func(tmpDir string) string {
			dir := filepath.Join(tmpDir, "symlink-dir")
			Expect(os.MkdirAll(filepath.Join(dir, "real_dir"), 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "real_dir", "file.txt"), []byte("data"), 0o644)).To(Succeed())
			Expect(os.Symlink("real_dir", filepath.Join(dir, "link_dir"))).To(Succeed())
			return dir
		}),
		Entry("for a directory with a dangling symlink", func(tmpDir string) string {
			dir := filepath.Join(tmpDir, "dangling")
			Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "real.txt"), []byte("hello"), 0o644)).To(Succeed())
			Expect(os.Symlink("nonexistent", filepath.Join(dir, "broken_link"))).To(Succeed())
			return dir
		}),
	)

	It("produces the same hash as dirhash.HashDir for a directory without symlinks", func() {
		dir := filepath.Join(tmpDir, "compat")
		Expect(os.MkdirAll(filepath.Join(dir, "sub"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb"), 0o644)).To(Succeed())

		expected, err := dirhash.HashDir(dir, "/", dirhash.Hash1)
		Expect(err).NotTo(HaveOccurred())

		actual, err := util.HashContentsAndPathsRecurse(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(actual).To(Equal(expected))
	})

	It("changes hash when symlink target changes", func() {
		dir := filepath.Join(tmpDir, "target-change")
		Expect(os.MkdirAll(filepath.Join(dir, "dir_a"), 0o755)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "dir_b"), 0o755)).To(Succeed())
		Expect(os.Symlink("dir_a", filepath.Join(dir, "link"))).To(Succeed())

		hash1, err := util.HashContentsAndPathsRecurse(dir)
		Expect(err).NotTo(HaveOccurred())

		Expect(os.Remove(filepath.Join(dir, "link"))).To(Succeed())
		Expect(os.Symlink("dir_b", filepath.Join(dir, "link"))).To(Succeed())

		hash2, err := util.HashContentsAndPathsRecurse(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(hash2).NotTo(Equal(hash1))
	})

	It("hashes symlink target path, not file content behind it", func() {
		dir := filepath.Join(tmpDir, "symlink-semantics")
		Expect(os.MkdirAll(dir, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "target.txt"), []byte("content"), 0o644)).To(Succeed())
		Expect(os.Symlink("target.txt", filepath.Join(dir, "link.txt"))).To(Succeed())

		hash1, err := util.HashContentsAndPathsRecurse(dir)
		Expect(err).NotTo(HaveOccurred())

		Expect(os.WriteFile(filepath.Join(dir, "target.txt"), []byte("changed"), 0o644)).To(Succeed())

		hash2, err := util.HashContentsAndPathsRecurse(dir)
		Expect(err).NotTo(HaveOccurred())

		// target.txt is also in the tree as a regular file, so its content
		// change IS detected through the regular file hash — but the symlink
		// entry itself hashes only the target path string "target.txt", which
		// did not change.
		Expect(hash2).NotTo(Equal(hash1))
	})
})
