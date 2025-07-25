package internal

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gen2brain/beeep"

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

type FileAccessMonitor struct {
	ProjectRoot string
	Logger      log.FieldLogger
}

func (m *FileAccessMonitor) Check(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		m.Logger.Warnf("Invalid path: %s", path)
		return false
	}

	if !strings.HasPrefix(absPath, m.ProjectRoot) {
		m.Logger.Warnf("Blocked external access: %s", absPath)
		return false
	}
	return true
}

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

// 获取项目根目录
func getProjectRoot() (string, error) {
	return os.Getwd()
}

// 增强型命令验证
func validateCommandSafety(cmdLine string, projectRoot string) bool {
	// 检查是否包含改变目录到外部的命令
	if strings.Contains(cmdLine, "cd ") {
		parts := strings.Split(cmdLine, "cd ")
		if len(parts) > 1 {
			targetDir := strings.TrimSpace(parts[1])
			if !isPathInProject(targetDir, projectRoot) {
				return false
			}
		}
	}

	// 检查文件操作命令
	fileCommands := []string{"cat ", "vim ", "less ", "head ", "tail ", "nano ", "cp ", "mv ", "rm ", "touch "}
	for _, cmd := range fileCommands {
		if strings.HasPrefix(cmdLine, cmd) {
			parts := strings.Fields(cmdLine)
			if len(parts) > 1 {
				filePath := parts[1]
				if !isPathInProject(filePath, projectRoot) {
					return false
				}
			}
		}
	}

	// 检查重定向操作
	if strings.Contains(cmdLine, ">") || strings.Contains(cmdLine, ">>") {
		parts := strings.Split(cmdLine, ">")
		if len(parts) > 1 {
			filePath := strings.TrimSpace(parts[1])
			if !isPathInProject(filePath, projectRoot) {
				return false
			}
		}
	}

	return true
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
	projectRoot       string
}

// judge a command is dangerous or not
func isDangerousCommand(command, projectRoot string) bool {
	// 检查是否尝试访问外部路径
	if strings.Contains(command, "..") {
		parts := strings.Fields(command)
		for _, part := range parts {
			if !isPathInProject(part, projectRoot) {
				return true
			}
		}
	}

	// 原有危险命令检测
	dangerousPrefixes := []string{"rm ", "sudo rm ", "dd ", "mkfs ", "chmod ", "chown "}
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(strings.TrimSpace(command), prefix) {
			return true
		}
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
	// 获取项目根目录
	projectRoot, err := getProjectRoot()
	if err != nil {
		h.logger.Errorf("Failed to get project root: %v", err)
		return
	}
	h.projectRoot = projectRoot

	// 显示安全提示
	_, _ = io.WriteString(sess, "\r\n=== SECURITY NOTICE ===")
	_, _ = io.WriteString(sess, "\r\nYou are restricted to: "+projectRoot)
	_, _ = io.WriteString(sess, "\r\nExternal file access is blocked\r\n\r\n")

	sessionID := sess.Context().Value(gssh.ContextKeySessionID).(string)
	defer emitClientLeftEvent(h.eventEmmiter, sessionID)

	ptyReq, winCh, isPty := sess.Pty()
	if !isPty {
		_, _ = io.WriteString(sess, "PTY is required.\n")
		_ = sess.Exit(1)
	}

	var (
		g    run.Group
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

			reader := uio.NewContextReader(ctx, sess)
			var currentCommand string
			for {
				buf := make([]byte, 1024)
				n, err := reader.Read(buf)
				if err != nil {
					return err
				}

				input := string(buf[:n])
				currentCommand += input

				// 检查命令是否安全
				if strings.Contains(input, "\r") || strings.Contains(input, "\n") {
					if !validateCommandSafety(currentCommand, h.projectRoot) {
						// 阻止命令并通知
						_, _ = ptmx.Write([]byte{3}) // 发送 Ctrl+C
						_, _ = sess.Write([]byte("\r\nSECURITY ALERT: Access outside project directory blocked\r\n"))
						_ = beeep.Notify("Security Alert", "Blocked external path access", "")
						currentCommand = ""
						continue
					}
					currentCommand = ""
				}

				if strings.Contains(input, "\x7f") && len(currentCommand) > 0 {
					// if input is backspace, remove the last character from the current command
					currentCommand = currentCommand[:len(currentCommand)-1]
				} else if strings.Contains(input, "\x03") {
					// if input is ctrl + c, clear the current command
					currentCommand = ""
				} else if strings.Contains(input, "\r") || strings.Contains(input, "\n") {
					// if the input is \r or \n, the current command is complete
					if isDangerousCommand(currentCommand, h.projectRoot) {
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
	cmd := exec.CommandContext(ctx, c[0], c[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", term))
	pty, err := startPty(cmd)

	return cmd, pty, err
}
