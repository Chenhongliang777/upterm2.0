<<<<<<< HEAD
package internal

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	gssh "github.com/charmbracelet/ssh"
	"github.com/gen2brain/beeep"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ------------------ 危险/警告命令黑名单 ------------------
var dangerList = []string{
	"rm", "sudo rm", "dd", "mkfs", "shutdown", "reboot", "halt", "poweroff",
	"wget", "curl", "nc", "ncat", "python", "perl", "ruby", "node",
}

var warnList = []string{
	"sudo", "mv", "cp", "chmod", "chown", "passwd", "visudo",
}

func isDangerousCommand(cmd string) bool {
	cmd = strings.TrimSpace(strings.ToLower(cmd))
	for _, d := range dangerList {
		if strings.HasPrefix(cmd, d) {
			return true
		}
	}
	return false
}

func isWarningCommand(cmd string) bool {
	cmd = strings.TrimSpace(strings.ToLower(cmd))
	for _, w := range warnList {
		if strings.HasPrefix(cmd, w) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------

type Server struct {
	Command           []string
	CommandEnv        []string
	ForceCommand      []string
	Signers           []ssh.Signer
	AuthorizedKeys    []ssh.PublicKey
	EventEmitter      *emitter.Emitter
	KeepAliveDuration time.Duration
	Stdin             *os.File
	Stdout            *os.File
	Logger            log.FieldLogger
	ReadOnly          bool
}

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	// 1. 锁定工作目录为当前目录
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get working dir: %w", err)
	}
	lockCmd := []string{"bash", "--norc", "--noprofile", "-c", "cd " + wd + " && exec bash"}
	s.Command = lockCmd
	s.ForceCommand = lockCmd

	writers := uio.NewMultiWriter(5)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.Stdin,
		s.Stdout,
		s.EventEmitter,
		writers,
	)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		teh := terminalEventHandler{
			eventEmitter: s.EventEmitter,
			logger:       s.Logger,
		}
		g.Add(func() error {
			return teh.Handle(ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			return cmd.Run()
		}, func(err error) {
			cmdCancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		sh := sessionHandler{
			forceCommand:      s.ForceCommand,
			ptmx:              ptmx,
			eventEmmiter:      s.EventEmitter,
			writers:           writers,
			keepAliveDuration: s.KeepAliveDuration,
			ctx:               ctx,
			logger:            s.Logger,
			readonly:          s.ReadOnly,
		}
		ph := publicKeyHandler{
			AuthorizedKeys: s.AuthorizedKeys,
			EventEmmiter:   s.EventEmitter,
			Logger:         s.Logger,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		srv := gssh.Server{
			HostSigners:      ss,
			Handler:          sh.HandleSession,
			Version:          upterm.HostSSHServerVersion,
			PublicKeyHandler: ph.HandlePublicKey,
			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.WithError(err).Error("connection failed")
			},
		}
		g.Add(func() error {
			return srv.Serve(l)
		}, func(err error) {
			cancel()
			_ = srv.Shutdown(ctx)
		})
	}

	return g.Run()
}

type publicKeyHandler struct {
	AuthorizedKeys []ssh.PublicKey
	EventEmmiter   *emitter.Emitter
	Logger         log.FieldLogger
}

func (h *publicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	checker := server.UserCertChecker{}
	auth, pk, err := checker.Authenticate(ctx.User(), key)
	if err != nil {
		h.Logger.WithError(err).Error("error parsing auth request from cert")
		return false
	}

	if len(h.AuthorizedKeys) == 0 {
		emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
		return true
	}
	for _, k := range h.AuthorizedKeys {
		if utils.KeysEqual(k, pk) {
			emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
			return true
		}
	}
	h.Logger.Info("unauthorized public key")
	return false
}

type sessionHandler struct {
	forceCommand      []string
	ptmx              *pty
	eventEmmiter      *emitter.Emitter
	writers           *uio.MultiWriter
	keepAliveDuration time.Duration
	ctx               context.Context
	logger            log.FieldLogger
	readonly          bool
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
		_, _ = io.WriteString(sess, "PTY is required.\n")
		_ = sess.Exit(1)
		return
	}

	var (
		g    run.Group
		ptmx = h.ptmx
	)

	// keep-alive
	{
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			ticker := time.NewTicker(h.keepAliveDuration)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					// 修复: SendRequest 只返回2个值
					_, err := sess.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil)
					if err != nil {
						h.logger.WithError(err).Debug("error sending keepalive")
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	if len(h.forceCommand) > 0 {
		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()

		cmd, newPty, err := startAttachCmd(ctx, h.forceCommand, ptyReq.Term)
		if err != nil {
			h.logger.WithError(err).Error("start force command failed")
			_ = sess.Exit(1)
			return
		}
		ptmx = newPty

		g.Add(func() error {
			_, err := io.Copy(sess, uio.NewContextReader(ctx, ptmx))
			return ptyError(err)
		}, func(err error) {
			cancel()
			ptmx.Close()
		})

		g.Add(func() error {
			return cmd.Wait()
		}, func(err error) {
			cancel()
			ptmx.Close()
		})
	} else {
		if err := h.writers.Append(sess); err != nil {
			_ = sess.Exit(1)
			return
		}
		defer h.writers.Remove(sess)
	}

	// window resize
	{
		ctx, cancel := context.WithCancel(h.ctx)
		tee := terminalEventEmitter{h.eventEmmiter}
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					tee.TerminalWindowChanged(sessionID, ptmx, win.Width, win.Height)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			tee.TerminalDetached(sessionID, ptmx)
			cancel()
		})
	}

	// -------------- 输入过滤 --------------
	if !h.readonly {
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			reader := uio.NewContextReader(ctx, sess)
			var currentLine strings.Builder
			var inEscape bool

			for {
				buf := make([]byte, 1024)
				n, err := reader.Read(buf)
				if err != nil {
					return err
				}

				// 处理读取到的数据
				processed := make([]byte, 0, n)
				for i := 0; i < n; i++ {
					b := buf[i]

					// 处理转义序列
					if inEscape {
						// 简单的转义序列处理 - 假设转义序列最多3个字符
						if b >= 0x40 && b <= 0x7E { // 转义序列结束
							inEscape = false
						}
						processed = append(processed, b)
						continue
					}

					switch b {
					case 0x03: // Ctrl+C
						currentLine.Reset()
						processed = append(processed, b)
					case 0x7F: // Backspace
						// 修复: 使用正确的方法处理 Backspace
						if currentLine.Len() > 0 {
							// 删除最后一个字符
							str := currentLine.String()
							currentLine.Reset()
							currentLine.WriteString(str[:len(str)-1])
						}
						processed = append(processed, b)
					case '\r', '\n':
						line := currentLine.String()
						currentLine.Reset()

						if isDangerousCommand(line) {
							// 发送Ctrl+C中断命令
							processed = append(processed, 0x03)
							// 显示警告消息
							warning := fmt.Sprintf("\r\n\x1b[31mSECURITY ALERT: Blocked dangerous command\x1b[0m\r\nCommand: %s\r\n\r\n", line)
							if _, err := sess.Write([]byte(warning)); err != nil {
								return err
							}
							_ = beeep.Notify("Security Alert", "Blocked: "+line, "")
						} else if isWarningCommand(line) {
							warning := fmt.Sprintf("\r\n\x1b[33mSECURITY WARNING: Risky command detected\x1b[0m\r\nCommand: %s\r\n\r\n", line)
							if _, err := sess.Write([]byte(warning)); err != nil {
								return err
							}
							_ = beeep.Notify("Security Warning", "Warning: "+line, "")
							processed = append(processed, b)
						} else {
							processed = append(processed, b)
						}
					case 0x1B: // ESC - 转义序列开始
						inEscape = true
						processed = append(processed, b)
					default:
						if b >= 0x20 && b <= 0x7E {
							currentLine.WriteByte(b)
						}
						processed = append(processed, b)
					}
				}

				// 将处理后的数据写入ptmx
				if _, err := ptmx.Write(processed); err != nil {
					return err
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	if err := g.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			_ = sess.Exit(exitError.ExitCode())
		} else {
			_ = sess.Exit(1)
		}
	} else {
		_ = sess.Exit(0)
	}
}

func emitClientJoinEvent(e *emitter.Emitter, sid string, auth *server.AuthRequest, pk ssh.PublicKey) {
	e.Emit(upterm.EventClientJoined, &api.Client{
		Id:                   sid,
		Version:              auth.ClientVersion,
		Addr:                 auth.RemoteAddr,
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
	})
}

func emitClientLeftEvent(e *emitter.Emitter, sid string) {
	e.Emit(upterm.EventClientLeft, sid)
}

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *pty, error) {
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), "TERM="+term)
	pty, err := startPty(cmd)
	return cmd, pty, err
}
=======
package internal

import (
	"context"
	"fmt"
	"github.com/gen2brain/beeep"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	gssh "github.com/charmbracelet/ssh"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/upterm"
	"github.com/owenthereal/upterm/utils"

	"github.com/oklog/run"
	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Command           []string
	CommandEnv        []string
	ForceCommand      []string
	Signers           []ssh.Signer
	AuthorizedKeys    []ssh.PublicKey
	EventEmitter      *emitter.Emitter
	KeepAliveDuration time.Duration
	Stdin             *os.File
	Stdout            *os.File
	Logger            log.FieldLogger
	ReadOnly          bool
}

func (s *Server) ServeWithContext(ctx context.Context, l net.Listener) error {
	writers := uio.NewMultiWriter(5)

	cmdCtx, cmdCancel := context.WithCancel(ctx)
	defer cmdCancel()
	cmd := newCommand(
		s.Command[0],
		s.Command[1:],
		s.CommandEnv,
		s.Stdin,
		s.Stdout,
		s.EventEmitter,
		writers,
	)
	ptmx, err := cmd.Start(cmdCtx)
	if err != nil {
		return fmt.Errorf("error starting command: %w", err)
	}

	var g run.Group
	{
		ctx, cancel := context.WithCancel(ctx)
		teh := terminalEventHandler{
			eventEmitter: s.EventEmitter,
			logger:       s.Logger,
		}
		g.Add(func() error {
			return teh.Handle(ctx)
		}, func(err error) {
			cancel()
		})
	}
	{
		g.Add(func() error {
			return cmd.Run()
		}, func(err error) {
			cmdCancel()
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		sh := sessionHandler{
			forceCommand:      s.ForceCommand,
			ptmx:              ptmx,
			eventEmmiter:      s.EventEmitter,
			writers:           writers,
			keepAliveDuration: s.KeepAliveDuration,
			ctx:               ctx,
			logger:            s.Logger,
			readonly:          s.ReadOnly,
		}
		ph := publicKeyHandler{
			AuthorizedKeys: s.AuthorizedKeys,
			EventEmmiter:   s.EventEmitter,
			Logger:         s.Logger,
		}

		var ss []gssh.Signer
		for _, signer := range s.Signers {
			ss = append(ss, signer)
		}

		server := gssh.Server{
			HostSigners:      ss,
			Handler:          sh.HandleSession,
			Version:          upterm.HostSSHServerVersion,
			PublicKeyHandler: ph.HandlePublicKey,
			ConnectionFailedCallback: func(conn net.Conn, err error) {
				s.Logger.WithError(err).Error("connection failed")
			},
		}
		g.Add(func() error {
			return server.Serve(l)
		}, func(err error) {
			// kill ssh sessionHandler
			cancel()
			// shut down ssh server
			_ = server.Shutdown(ctx)
		})
	}

	return g.Run()
}

type publicKeyHandler struct {
	AuthorizedKeys []ssh.PublicKey
	EventEmmiter   *emitter.Emitter
	Logger         log.FieldLogger
}

func (h *publicKeyHandler) HandlePublicKey(ctx gssh.Context, key gssh.PublicKey) bool {
	checker := server.UserCertChecker{}
	auth, pk, err := checker.Authenticate(ctx.User(), key)
	if err != nil {
		h.Logger.WithError(err).Error("error parsing auth request from cert")
		return false
	}

	// TODO: sshproxy already rejects unauthorized keys
	// Does host still need to check them?
	if len(h.AuthorizedKeys) == 0 {
		emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
		return true
	}

	for _, k := range h.AuthorizedKeys {
		if utils.KeysEqual(k, pk) {
			emitClientJoinEvent(h.EventEmmiter, ctx.SessionID(), auth, pk)
			return true
		}
	}

	h.Logger.Info("unauthorized public key")
	return false
}

type sessionHandler struct {
	forceCommand      []string
	ptmx              *pty
	eventEmmiter      *emitter.Emitter
	writers           *uio.MultiWriter
	keepAliveDuration time.Duration
	ctx               context.Context
	logger            log.FieldLogger
	readonly          bool
}

// judge a command is dangerous or not
func isDangerousCommand(command string) bool {
	if strings.HasPrefix(strings.TrimSpace(command), "rm") {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(command), "sudo rm") {
		return true
	}
	return false
}

// judge a command is warning or not
func isWarningCommand(command string) bool {
	if strings.HasPrefix(strings.TrimSpace(command), "sudo") {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(command), "mv") {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(command), "cp") {
		return true
	}

	return false
}

func (h *sessionHandler) HandleSession(sess gssh.Session) {
	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
		_, _ = io.WriteString(sess, "PTY is required.\n")
		_ = sess.Exit(1)
	}

	var (
		g    run.Group
		err  error
		ptmx = h.ptmx
	)

	// simulate openssh keepalive
	{
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			ticker := time.NewTicker(h.keepAliveDuration)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					if _, err := sess.SendRequest(upterm.OpenSSHKeepAliveRequestType, true, nil); err != nil {
						h.logger.WithError(err).Debug("error pinging client to keepalive")
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	if len(h.forceCommand) > 0 {
		var cmd *exec.Cmd

		ctx, cancel := context.WithCancel(h.ctx)
		defer cancel()

		cmd, ptmx, err = startAttachCmd(ctx, h.forceCommand, ptyReq.Term)
		if err != nil {
			h.logger.WithError(err).Error("error starting force command")
			_ = sess.Exit(1)
			return
		}

		{
			// reattach output
			g.Add(func() error {
				_, err := io.Copy(sess, uio.NewContextReader(ctx, ptmx))
				return ptyError(err)
			}, func(err error) {
				cancel()
				ptmx.Close()
			})
		}
		{
			g.Add(func() error {
				return cmd.Wait()
			}, func(err error) {
				cancel()
				ptmx.Close()
			})
		}
	} else {
		// output
		if err := h.writers.Append(sess); err != nil {
			_ = sess.Exit(1)
			return
		}

		defer h.writers.Remove(sess)
	}

	{
		// pty
		ctx, cancel := context.WithCancel(h.ctx)
		tee := terminalEventEmitter{h.eventEmmiter}
		g.Add(func() error {
			for {
				select {
				case win := <-winCh:
					tee.TerminalWindowChanged(sessionID, ptmx, win.Width, win.Height)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}, func(err error) {
			tee.TerminalDetached(sessionID, ptmx)
			cancel()
		})
	}

	// if a readonly session has been requested, don't connect stdin
	if h.readonly {
		// write to client to notify them that they have connected to a read-only session
		_, _ = io.WriteString(sess, "\r\n=== Attached to read-only session ===\r\n\r\n")
	} else {
		// input
		ctx, cancel := context.WithCancel(h.ctx)
		g.Add(func() error {
			// previous
			//_, err := io.Copy(ptmx, uio.NewContextReader(ctx, sess))
			//return err

			// new
			reader := uio.NewContextReader(ctx, sess)
			var currentCommand string
			for {
				buf := make([]byte, 1024)
				n, err := reader.Read(buf)
				if err != nil {
					return err
				}

				input := string(buf[:n])

				if strings.Contains(input, "\x7f") && len(currentCommand) > 0 {
					// if input is backspace, remove the last character from the current command
					currentCommand = currentCommand[:len(currentCommand)-1]
				} else if strings.Contains(input, "\x03") {
					// if input is ctrl + c, clear the current command
					currentCommand = ""
				} else if strings.Contains(input, "\r") || strings.Contains(input, "\n") {
					// if the input is \r or \n, the current command is complete
					if isDangerousCommand(currentCommand) {
						// press ctrl + c
						_, err = ptmx.Write([]byte{3})
						if err != nil {
							return err
						}

						// write to client to notify them that they have tried to run a dangerous command
						_, _ = io.WriteString(sess, "\r\nDanger"+
							"\r\nYou have attempted to execute a dangerous command: "+currentCommand+
							"\r\nThis command has been forbidden.\r\n")

						// beeep
						_ = beeep.Notify("Danger", "The collaborator has tried to run a dangerous command: "+currentCommand+". This command has been forbidden.", "")

						// reset current command
						currentCommand = ""

						continue
					} else if isWarningCommand(currentCommand) {
						_, err = ptmx.Write(buf[:n])

						// write to client to notify them that they have tried to run a warning command
						_, _ = io.WriteString(sess, "\r\nWarning"+
							"\r\nYou have attempted to execute a risky command: "+currentCommand+
							"\r\nThis command will not be forbidden, but please be careful when executing it.\r\n")

						// beeep
						_ = beeep.Notify("Warning", "The collaborator has tried to run a risky command: "+currentCommand+". This command will not be forbidden, but please be careful when executing it.", "")

						// reset current command
						currentCommand = ""

						continue
					}

					// reset current command
					currentCommand = ""
				} else {
					// otherwise, add the input to the current command
					currentCommand += input
				}

				_, err = ptmx.Write(buf[:n])
				if err != nil {
					return err
				}
			}
		}, func(err error) {
			cancel()
		})
	}

	if err := g.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			_ = sess.Exit(exitError.ExitCode())
		} else {
			_ = sess.Exit(1)
		}
	} else {
		_ = sess.Exit(0)
	}
}

func emitClientJoinEvent(eventEmmiter *emitter.Emitter, sessionID string, auth *server.AuthRequest, pk ssh.PublicKey) {
	c := &api.Client{
		Id:                   sessionID,
		Version:              auth.ClientVersion,
		Addr:                 auth.RemoteAddr,
		PublicKeyFingerprint: utils.FingerprintSHA256(pk),
	}
	eventEmmiter.Emit(upterm.EventClientJoined, c)
}

func emitClientLeftEvent(eventEmmiter *emitter.Emitter, sessionID string) {
	eventEmmiter.Emit(upterm.EventClientLeft, sessionID)
}

func startAttachCmd(ctx context.Context, c []string, term string) (*exec.Cmd, *pty, error) {
	projectRoot, err := os.Getwd()
    if err != nil {
        return nil, nil, fmt.Errorf("failed to get project root: %v", err)
    }
    if err := ValidateCommand(c[0], c[1:], projectRoot); err != nil {
        return nil, nil, fmt.Errorf("command validation failed: %v", err)
    }
    cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := startPty(cmd)

	return cmd, pty, err
}
>>>>>>> 6f27ba9c5b30968948927d9e2f0d6ad0a98d60f5
