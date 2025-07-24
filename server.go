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
