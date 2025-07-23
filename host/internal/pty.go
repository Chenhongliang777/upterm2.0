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
	projectRoot := "d:\\upterm"
	// 检查工作目录
	if cmd.Dir != "" {
		absDir, err := filepath.Abs(cmd.Dir)
		if err != nil {
			return fmt.Errorf("路径检查失败: %v", err)
		}
		if !strings.HasPrefix(absDir, projectRoot) {
			return fmt.Errorf("禁止访问项目外目录: %s", absDir)
		}
	} else {
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("获取当前目录失败: %v", err)
		}
		if !strings.HasPrefix(currentDir, projectRoot) {
			return fmt.Errorf("当前目录不在项目内: %s", currentDir)
		}
	}

	// 检查命令参数中的路径
	for _, arg := range cmd.Args[1:] {
		if strings.Contains(arg, "..") || strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "\\") {
			absPath, err := filepath.Abs(arg)
			if err != nil {
				return fmt.Errorf("路径解析失败: %v", err)
			}
			if !strings.HasPrefix(absPath, projectRoot) {
				return fmt.Errorf("禁止访问项目外路径: %s", arg)
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

// Linux kernel return EIO when attempting to read from a master pseudo
// terminal which no longer has an open slave. So ignore error here.
// See https://github.com/creack/pty/issues/21
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

// Pty is a wrapper of the pty *os.File that provides a read/write mutex.
// This is to prevent data race that might happen for reszing, reading and closing.
// See ftests failure:
// * https://travis-ci.org/owenthereal/upterm/jobs/632489866
// * https://travis-ci.org/owenthereal/upterm/jobs/632458125
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
