//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"syscall"
	"time"
)

// synProbe realiza un escaneo SYN half-open: envía un SYN y clasifica la respuesta.
//   - SYN-ACK -> abierto
//   - RST     -> cerrado
//   - nada    -> filtrado
//
// Requiere un socket raw (privilegios root). Solo IPv4.
func synProbe(ctx context.Context, j job) Result {
	res := Result{Host: j.host, Port: j.port, Proto: "tcp", State: "filtered", Service: serviceName(j.port)}

	dstIP := resolveIPv4(j.host)
	if dstIP == nil {
		res.State = "closed"
		return res
	}
	srcIP := localIPv4(dstIP)
	if srcIP == nil {
		return res
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return res
	}
	defer syscall.Close(fd)

	srcPort := uint16(1024 + rand.Intn(60000))
	pkt := buildSYN(srcIP, dstIP, srcPort, uint16(j.port))

	var sa syscall.SockaddrInet4
	sa.Port = j.port
	copy(sa.Addr[:], dstIP.To4())

	tv := syscall.NsecToTimeval(int64(*timeout))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	if err := syscall.Sendto(fd, pkt, 0, &sa); err != nil {
		return res
	}

	buf := make([]byte, 1500)
	deadline := time.Now().Add(*timeout)
	dst4 := dstIP.To4()

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return res
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			break // timeout u otro error -> filtrado
		}
		if n < 40 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+20 {
			continue
		}
		if buf[9] != syscall.IPPROTO_TCP {
			continue
		}
		if !ipEqual(buf[12:16], dst4) { // origen = nuestro objetivo
			continue
		}
		tcp := buf[ihl:n]
		sp := binary.BigEndian.Uint16(tcp[0:2])
		dp := binary.BigEndian.Uint16(tcp[2:4])
		if sp != uint16(j.port) || dp != srcPort {
			continue
		}
		const flagFIN, flagSYN, flagRST, flagACK = 0x01, 0x02, 0x04, 0x10
		flags := tcp[13]
		if flags&flagRST != 0 {
			res.State = "closed"
			return res
		}
		if flags&flagSYN != 0 && flags&flagACK != 0 {
			res.State = "open"
			return res
		}
	}
	return res
}

func resolveIPv4(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

func localIPv4(dst net.IP) net.IP {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "80"))
	if err != nil {
		return nil
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.To4()
	}
	return nil
}

func ipEqual(a []byte, b net.IP) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

// buildSYN construye un segmento TCP SYN con su checksum (el kernel añade la cabecera IP).
func buildSYN(src, dst net.IP, srcPort, dstPort uint16) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], rand.Uint32()) // número de secuencia
	tcp[12] = 5 << 4                                    // data offset = 5 palabras (20 bytes)
	tcp[13] = 0x02                                      // flag SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)       // window
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src.To4(), dst.To4(), tcp))
	return tcp
}

func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))

	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(pseudo)
	add(tcp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
