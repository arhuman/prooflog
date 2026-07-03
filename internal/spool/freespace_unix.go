//go:build unix

package spool

import "syscall"

// unixFreeSpace reports bytes available to a non-root user on the filesystem
// backing dir.
func unixFreeSpace(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

func init() { defaultFreeSpace = unixFreeSpace }
