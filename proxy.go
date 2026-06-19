package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// socks contiene la configuración de un proxy SOCKS5.
type socks struct {
	addr string
	user string
	pass string
}

// socksProxy es el proxy activo (nil = conexión directa).
var socksProxy *socks

// parseProxy interpreta "[socks5://][user:pass@]host:puerto".
func parseProxy(s string) (*socks, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "socks5://")

	p := &socks{}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		cred := s[:at]
		s = s[at+1:]
		if c := strings.IndexByte(cred, ':'); c >= 0 {
			p.user, p.pass = cred[:c], cred[c+1:]
		} else {
			p.user = cred
		}
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return nil, fmt.Errorf("dirección de proxy inválida %q: %v", s, err)
	}
	p.addr = s
	return p, nil
}

// dial abre una conexión TCP hacia addr a través del proxy SOCKS5.
func (p *socks) dial(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: *timeout}).DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(*timeout))
	if err := p.handshake(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{}) // limpiamos el deadline del handshake
	return conn, nil
}

func (p *socks) handshake(conn net.Conn, addr string) error {
	// Saludo: anunciamos los métodos de autenticación soportados.
	if p.user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("respuesta SOCKS inválida")
	}
	switch resp[1] {
	case 0x00: // sin autenticación
	case 0x02:
		if err := p.authUserPass(conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("método de autenticación SOCKS no soportado (0x%02x)", resp[1])
	}

	// Petición CONNECT.
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("hostname demasiado largo para SOCKS5")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Respuesta del CONNECT.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("el proxy rechazó la conexión (código 0x%02x)", head[1])
	}

	// Descartamos BND.ADDR + BND.PORT según el tipo de dirección.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return fmt.Errorf("tipo de dirección desconocido en la respuesta SOCKS")
	}
	_, err = io.CopyN(io.Discard, conn, int64(skip))
	return err
}

func (p *socks) authUserPass(conn net.Conn) error {
	buf := []byte{0x01, byte(len(p.user))}
	buf = append(buf, p.user...)
	buf = append(buf, byte(len(p.pass)))
	buf = append(buf, p.pass...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("autenticación SOCKS5 rechazada")
	}
	return nil
}
