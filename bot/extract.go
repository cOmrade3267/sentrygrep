package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractTarball unpacks a gzipped tar stream (as returned by GitHub's
// tarball endpoint) into destDir. GitHub wraps the repo contents in a
// single top-level directory like "owner-repo-abc1234/" — we strip that
// so destDir ends up containing the file tree directly, ready to hand
// to scanner.py's --target flag.
func extractTarball(src io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		parts := strings.SplitN(header.Name, "/", 2)
		if len(parts) < 2 {
			continue // the top-level dir entry itself
		}
		relPath := parts[1]
		if relPath == "" {
			continue
		}

		targetPath := filepath.Join(destDir, relPath)

		// Guard against path traversal in the tar entry itself
		// (defense in depth — same bug class as the CWE-78/traversal
		// issues this whole tool exists to catch).
		if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes destination: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("creating dir %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("creating parent dir for %s: %w", targetPath, err)
			}
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("creating file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("writing file %s: %w", targetPath, err)
			}
			outFile.Close()
		}
	}

	return nil
}

// splitFullName splits GitHub's "owner/repo" format into its two parts.
func splitFullName(fullName string) (owner, repo string) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}