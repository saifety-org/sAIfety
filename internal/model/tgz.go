package model

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// fetchTgz downloads a .tgz and extracts the member whose base name equals
// a.Extract into dst.
func fetchTgz(w io.Writer, a Artifact, dst, tmp string) error {
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(a.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s not found in archive", a.Extract)
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != a.Extract || hdr.Typeflag != tar.TypeReg {
			continue
		}
		f, err := os.Create(tmp)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		f.Close()
		return os.Rename(tmp, dst)
	}
}
