//go:build linux

// init is the initramfs PID 1 for an isolated QEMU user-networked appliance.
// The Alpine virt initramfs needs a virtio-net-pci device, not e1000.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func mountFilesystems() error {
	for _, fs := range []struct{ name, dir, kind string }{
		{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"},
	} {
		if err := os.MkdirAll(fs.dir, 0755); err != nil {
			return err
		}
		if err := syscall.Mount(fs.name, fs.dir, fs.kind, 0, ""); err != nil && err != syscall.EBUSY {
			return fmt.Errorf("mount %s: %w", fs.dir, err)
		}
	}
	return nil
}

func enableSerialLog() {
	serial, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, serial))
	}
}

// moduleOrder resolves only modules included in this initramfs, including
// dependencies already ordered by modules.dep.
func moduleOrder(root, target string) ([]string, error) {
	f, err := os.Open(filepath.Join(root, "modules.dep"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	deps := make(map[string][]string)
	var module string
	s := bufio.NewScanner(f)
	for s.Scan() {
		name, rest, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		deps[name] = strings.Fields(rest)
		if filepath.Base(name) == target+".ko" {
			module = name
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if module == "" {
		return nil, fmt.Errorf("module %s not found in %s", target, root)
	}
	var result []string
	seen := make(map[string]bool)
	active := make(map[string]bool)
	var visit func(string) error
	visit = func(name string) error {
		if active[name] {
			return fmt.Errorf("cyclic module dependency: %s", name)
		}
		if seen[name] {
			return nil
		}
		children, ok := deps[name]
		if !ok {
			return fmt.Errorf("missing dependency %s", name)
		}
		active[name] = true
		for _, child := range children {
			if err := visit(child); err != nil {
				return err
			}
		}
		delete(active, name)
		seen[name] = true
		result = append(result, filepath.Join(root, name))
		return nil
	}
	if err := visit(module); err != nil {
		return nil, err
	}
	return result, nil
}

func loadVirtioNet() error {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return err
	}
	var release []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		release = append(release, byte(c))
	}
	modules, err := moduleOrder(filepath.Join("/lib/modules", string(release)), "virtio_net")
	if err != nil {
		return err
	}
	for _, path := range modules {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return fmt.Errorf("empty module %s", path)
		}
		empty := []byte{0}
		_, _, errno := syscall.Syscall(syscall.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&empty[0])))
		if errno != 0 && errno != syscall.EEXIST {
			return fmt.Errorf("load %s: %w", path, errno)
		}
	}
	return nil
}

// Linux ifreq is 40 bytes on the x86_64 kernel used by Alpine virt.
type ifreq struct {
	name [16]byte
	data [24]byte
}

func ioctl(fd int, request uintptr, req *ifreq) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(req)))
	if errno != 0 {
		return errno
	}
	return nil
}

func setInterface(name string, address net.IP, mask net.IP) error {
	if len(name) == 0 || len(name) >= 16 || address.To4() == nil || mask.To4() == nil {
		return fmt.Errorf("invalid interface configuration for %q", name)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var req ifreq
	copy(req.name[:], name)
	for _, setting := range []struct {
		request uintptr
		ip      net.IP
	}{{syscall.SIOCSIFADDR, address}, {syscall.SIOCSIFNETMASK, mask}} {
		req.data = [24]byte{}
		binary.NativeEndian.PutUint16(req.data[:2], syscall.AF_INET)
		copy(req.data[4:8], setting.ip.To4())
		if err := ioctl(fd, setting.request, &req); err != nil {
			return fmt.Errorf("%s address/mask: %w", name, err)
		}
	}
	req.data = [24]byte{}
	if err := ioctl(fd, syscall.SIOCGIFFLAGS, &req); err != nil {
		return err
	}
	flags := binary.NativeEndian.Uint16(req.data[:2]) | syscall.IFF_UP
	binary.NativeEndian.PutUint16(req.data[:2], flags)
	if err := ioctl(fd, syscall.SIOCSIFFLAGS, &req); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	return nil
}

func configureNetwork() error {
	if err := setInterface("lo", net.IPv4(127, 0, 0, 1), net.IPv4(255, 0, 0, 0)); err != nil {
		return err
	}
	// virtio transport is built in to Alpine's virt kernel; the NIC is a module.
	if err := loadVirtioNet(); err != nil {
		log.Printf("virtio_net module: %v (checking for an already available NIC)", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback == 0 {
				log.Printf("configuring %s as 10.0.2.15/24", iface.Name)
				return setInterface(iface.Name, net.IPv4(10, 0, 2, 15), net.IPv4(255, 255, 255, 0))
			}
		}
		if time.Now().After(deadline) {
			return errors.New("no network interface; use QEMU virtio-net-pci")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func newTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "purego-appliance"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(10, 0, 2, 15)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, nil
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	return mux
}

func serve(ctx context.Context) error {
	tlsConfig, err := newTLSConfig()
	if err != nil {
		return err
	}
	httpListener, err := net.Listen("tcp", ":80")
	if err != nil {
		return err
	}
	defer httpListener.Close()
	httpsListener, err := net.Listen("tcp", ":443")
	if err != nil {
		return err
	}
	defer httpsListener.Close()
	handler := healthHandler()
	plain := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	secure := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsConfig}
	errs := make(chan error, 2)
	go func() { errs <- plain.Serve(httpListener) }()
	go func() { errs <- secure.Serve(tls.NewListener(httpsListener, tlsConfig)) }()
	log.Print("HTTP :80 and TLS 1.3 HTTPS :443 ready")
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = plain.Shutdown(shutdown)
	_ = secure.Shutdown(shutdown)
	return err
}

func main() {
	log.SetFlags(0)
	if os.Getpid() != 1 {
		log.Print("refusing to configure networking outside PID 1")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// Reap any orphaned children adopted by PID 1.
	children := make(chan os.Signal, 1)
	signal.Notify(children, syscall.SIGCHLD)
	defer signal.Stop(children)
	go func() {
		for range children {
			for {
				pid, _ := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
				if pid <= 0 {
					break
				}
			}
		}
	}()
	if err := mountFilesystems(); err != nil {
		log.Printf("startup: %v", err)
	} else {
		enableSerialLog()
		if err := configureNetwork(); err != nil {
			log.Printf("startup: %v", err)
		} else if err := serve(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server: %v", err)
		}
	}
	// Exiting PID 1 panics the kernel; stay alive after startup/server errors.
	<-ctx.Done()
	log.Print("shutting down")
	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		log.Printf("poweroff: %v", err)
		select {}
	}
}
