package tor

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// signalNewNYM authenticates with Tor's control cookie and requests a new
// identity. It deliberately does not claim that the resulting exit IP changes;
// callers must verify the observed exit afterwards.
func signalNewNYM(ctx context.Context, controlPort int, dataDirectory string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	cookiePath := filepath.Join(dataDirectory, "control_auth_cookie")
	cookie, err := os.ReadFile(cookiePath)
	if err != nil {
		return fmt.Errorf("read Tor control cookie: %w", err)
	}
	if len(cookie) == 0 {
		return errors.New("Tor control cookie is empty")
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", controlPort))
	if err != nil {
		return fmt.Errorf("connect Tor control port: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)
	if err := torControlCommand(conn, reader, "AUTHENTICATE "+hex.EncodeToString(cookie)); err != nil {
		return fmt.Errorf("Tor control authenticate: %w", err)
	}
	if err := torControlCommand(conn, reader, "SIGNAL NEWNYM"); err != nil {
		return fmt.Errorf("Tor SIGNAL NEWNYM: %w", err)
	}
	_ = torControlCommand(conn, reader, "QUIT")
	return nil
}

func torControlCommand(conn net.Conn, reader *bufio.Reader, command string) error {
	if _, err := fmt.Fprintf(conn, "%s\r\n", command); err != nil {
		return err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if len(line) < 3 {
			continue
		}
		if strings.HasPrefix(line, "250 ") || line == "250" {
			return nil
		}
		if strings.HasPrefix(line, "250-") || strings.HasPrefix(line, "250+") {
			continue
		}
		if len(line) >= 3 && line[0] >= '4' && line[0] <= '5' {
			return errors.New(line)
		}
	}
}
