package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

type AppConfig struct {
	YggdrasilConfig string `json:"yggdrasil_config"`
	SocksListen     string `json:"socks_listen"`
	ExitRemoteAddr  string `json:"exit_remote_addr"`
	ExitRemotePort  int    `json:"exit_remote_port"`
	ExitLocalPort   int    `json:"exit_local_port"`
	InnerIP         string `json:"inner_ip"`
	InnerPrefixLen  int    `json:"inner_prefix_len"`
	DNSServer       string `json:"dns_server"`
	DNSServer2      string `json:"dns_server2"`
	MTU             int    `json:"mtu"`
}

func main() {
	configPath := flag.String("config", "config.json", "path to client config JSON")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	appCfg, err := loadAppConfig(*configPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	if err := appCfg.Validate(); err != nil {
		fatalf("invalid config: %v", err)
	}

	stdlog := log.New(os.Stdout, "", log.Flags())
	for _, level := range []string{"error", "warn", "info"} {
		stdlog.EnableLevel(level)
	}

	ygg, err := StartYggdrasil(appCfg.YggdrasilConfig, stdlog)
	if err != nil {
		fatalf("start yggdrasil: %v", err)
	}
	defer ygg.Stop()

	fmt.Printf("Yggdrasil IPv6: %s\n", ygg.Address())
	fmt.Printf("Inner IPv4:     %s/%d\n", appCfg.InnerIP, appCfg.InnerPrefixLen)
	fmt.Printf("Exitd:          [%s]:%d, local UDP port %d\n", appCfg.ExitRemoteAddr, appCfg.ExitRemotePort, appCfg.ExitLocalPort)

	tunnel, err := NewExitTunnel(ygg, appCfg.ExitRemoteAddr, appCfg.ExitRemotePort, appCfg.ExitLocalPort, appCfg.MTU)
	if err != nil {
		fatalf("open exit tunnel: %v", err)
	}

	ns, err := NewExitNetStack(tunnel, appCfg.InnerIP, appCfg.InnerPrefixLen, appCfg.MTU)
	if err != nil {
		fatalf("create netstack: %v", err)
	}
	defer ns.Close()

	server := &SocksServer{
		ListenAddr: appCfg.SocksListen,
		Net:        ns,
		DNSServers: []string{appCfg.DNSServer, appCfg.DNSServer2},
	}

	go func() {
		if err := server.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
			fatalf("socks server: %v", err)
		}
	}()

	fmt.Printf("SOCKS5:         %s\n", appCfg.SocksListen)
	fmt.Println("Ready. Press Ctrl+C to stop.")
	<-ctx.Done()
	fmt.Println("Stopping...")
	time.Sleep(200 * time.Millisecond)
}

func loadAppConfig(path string) (*AppConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *AppConfig) Validate() error {
	if c.YggdrasilConfig == "" {
		return fmt.Errorf("yggdrasil_config is required")
	}
	if c.SocksListen == "" {
		c.SocksListen = "127.0.0.1:1080"
	}
	if c.ExitRemoteAddr == "" {
		return fmt.Errorf("exit_remote_addr is required")
	}
	remoteIP := net.ParseIP(c.ExitRemoteAddr)
	if remoteIP == nil || remoteIP.To4() != nil || remoteIP.To16() == nil {
		return fmt.Errorf("exit_remote_addr must be Yggdrasil IPv6")
	}
	if c.ExitRemotePort <= 0 || c.ExitRemotePort > 65535 {
		return fmt.Errorf("exit_remote_port out of range")
	}
	if c.ExitLocalPort <= 0 || c.ExitLocalPort > 65535 {
		return fmt.Errorf("exit_local_port out of range")
	}
	innerIP := net.ParseIP(c.InnerIP)
	if innerIP == nil || innerIP.To4() == nil {
		return fmt.Errorf("inner_ip must be IPv4")
	}
	if c.InnerPrefixLen <= 0 || c.InnerPrefixLen > 32 {
		return fmt.Errorf("inner_prefix_len must be 1..32")
	}
	if c.DNSServer == "" {
		c.DNSServer = "1.1.1.1"
	}
	dnsIP := net.ParseIP(c.DNSServer)
	if dnsIP == nil || dnsIP.To4() == nil {
		return fmt.Errorf("dns_server must be IPv4")
	}
	if c.DNSServer2 != "" {
		dnsIP2 := net.ParseIP(c.DNSServer2)
		if dnsIP2 == nil || dnsIP2.To4() == nil {
			return fmt.Errorf("dns_server2 must be IPv4")
		}
	}
	if c.MTU == 0 {
		c.MTU = 1280
	}
	if c.MTU < 576 || c.MTU > 1500 {
		return fmt.Errorf("mtu must be 576..1500")
	}
	return nil
}

type YggNode struct {
	core   *core.Core
	iprwc  *ipv6rwc.ReadWriteCloser
	logger *log.Logger
	mu     sync.Mutex
}

func StartYggdrasil(configPath string, logger *log.Logger) (*YggNode, error) {
	cfg := config.GenerateConfig()
	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := cfg.ReadFrom(f); err != nil {
		return nil, err
	}

	options := []core.SetupOption{
		core.NodeInfo(cfg.NodeInfo),
		core.NodeInfoPrivacy(cfg.NodeInfoPrivacy),
	}
	for _, listen := range cfg.Listen {
		options = append(options, core.ListenAddress(listen))
	}
	for _, peer := range cfg.Peers {
		options = append(options, core.Peer{URI: peer})
	}
	for intf, peers := range cfg.InterfacePeers {
		for _, peer := range peers {
			options = append(options, core.Peer{URI: peer, SourceInterface: intf})
		}
	}
	for _, allowed := range cfg.AllowedPublicKeys {
		k, err := hex.DecodeString(allowed)
		if err != nil {
			return nil, fmt.Errorf("allowed public key %q: %w", allowed, err)
		}
		options = append(options, core.AllowedPublicKey(k[:]))
	}

	c, err := core.New(cfg.Certificate, logger, options...)
	if err != nil {
		return nil, err
	}

	rwc := ipv6rwc.NewReadWriteCloser(c)
	mtu := cfg.IfMTU
	if rwc.MaxMTU() < mtu {
		mtu = rwc.MaxMTU()
	}
	rwc.SetMTU(mtu)

	return &YggNode{core: c, iprwc: rwc, logger: logger}, nil
}

func (n *YggNode) Stop() {
	if n.core != nil {
		n.core.Stop()
	}
}

func (n *YggNode) Address() net.IP {
	addr := n.core.Address()
	return net.IP(addr[:])
}

func (n *YggNode) PublicKeyHex() string {
	return hex.EncodeToString(n.core.PublicKey())
}

func AddressForConfig(path string) (net.IP, error) {
	cfg := config.GenerateConfig()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := cfg.ReadFrom(f); err != nil {
		return nil, err
	}
	privateKey := ed25519.PrivateKey(cfg.PrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	addr := address.AddrForKey(publicKey)
	return net.IP(addr[:]), nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
