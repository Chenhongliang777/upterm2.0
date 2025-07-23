package internal

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	ptylib "github.com/creack/pty"
)

// 检查命令是否尝试访问项目外路径
func checkCommand(cmd *exec.Cmd) error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get project root: %v", err)
	}
	projectRoot = filepath.Clean(projectRoot)

	// 检查工作目录
	if cmd.Dir != "" {
		absDir, err := filepath.Abs(cmd.Dir)
		if err != nil {
			return fmt.Errorf("invalid working directory: %v", err)
		}
		absDir = filepath.Clean(absDir)
		if !strings.HasPrefix(absDir, projectRoot) {
			return fmt.Errorf("access denied: working directory outside project root")
		}
	}

	// 仅检查看起来像路径的参数
	for _, arg := range cmd.Args[1:] {
		if strings.Contains(arg, "..") || filepath.IsAbs(arg) {
			absPath, err := filepath.Abs(arg)
			if err != nil {
				continue // 忽略无效路径
			}

			absPath = filepath.Clean(absPath)
			if !strings.HasPrefix(absPath, projectRoot) {
				return fmt.Errorf("access denied: path outside project root: %s", arg)
			}
		}
	}
	return nil
}

func startPty(c *exec.Cmd) (*pty, error) {
	// 执行命令前进行路径检查
	if err := checkCommand(c); err != nil {
		return nil, fmt.Errorf("命令被拒绝: %v", err)
	}

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
	sync.RWMutex
}

func (pty *pty) Setsize(h, w int) error {
	pty.RLock()
	defer pty.RUnlock()

	size := &ptylib.Winsize{
		Rows: uint16(h),
		Cols: uint16(w),
	}
	return ptylib.Setsize(pty.File, size)
}

func (pty *pty) Read(p []byte) (n int, err error) {
	pty.RLock()
	defer pty.RUnlock()

	return pty.File.Read(p)
}

func (pty *pty) Close() error {
	pty.Lock()
	defer pty.Unlock()

	return pty.File.Close()
}
