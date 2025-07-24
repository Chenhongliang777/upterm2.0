package internal

import (
	"os"
	"os/exec"
	"sync"
	"syscall"

	ptylib "github.com/creack/pty"
)

func startPty(c *exec.Cmd) (*pty, error) {
	f, err := ptylib.Start(c)
	if err != nil {
		return nil, err
	}

	return wrapPty(f), nil
}

func ptyError(err error) error {
	if pathErr, ok := err.(*os.PathError); !ok || pathErr.Err != syscall.EIO {
		return err
	}

	return nil
}

func getPtysize(f *os.File) (h, w int, err error) {
	return ptylib.Getsize(f)
}

func wrapPty(f *os.File) *pty {
	return &pty{File: f}
}

type pty struct {
	*os.File
	sync.Mutex
}

func (pty *pty) Setsize(h, w int) error {
	pty.Lock()
	defer pty.Unlock()

	size := &ptylib.Winsize{
		Rows: uint16(h),
		Cols: uint16(w),
	}
	return ptylib.Setsize(pty.File, size)
}

func (pty *pty) Read(p []byte) (n int, err error) {
	pty.Lock()
	defer pty.Unlock()

	return pty.File.Read(p)
}

func (pty *pty) Close() error {
	pty.Lock()
	defer pty.Unlock()

	return pty.File.Close()
}
