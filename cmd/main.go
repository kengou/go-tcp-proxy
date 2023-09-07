package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/kengou/go-tcp-proxy/pkg/proxy"
	"k8s.io/klog/v2"
)

var (
	version = "0.0.1"
	matchid = uint64(0)

	localAddr  = flag.String("l", ":443", "local address")
	remoteAddr = flag.String("r", fmt.Sprintf("%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")), "remote address")
	nagles     = flag.Bool("n", false, "disable nagles algorithm")
	hex        = flag.Bool("h", false, "output hex")
	unwrapTLS  = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match      = flag.String("match", "", "match regex (in the form 'regex')")
	replace    = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	klog.Infof("go-tcp-proxy (%s) proxing from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		klog.Errorf("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		klog.Errorf("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		klog.Errorf("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			klog.Errorf("Failed to accept connection '%s'", err)
			continue
		}

		var p *proxy.Proxy
		if *unwrapTLS {
			klog.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.Nagles = *nagles
		p.OutputHex = *hex

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		klog.Errorf("Invalid match regex: %s", err)
		return nil
	}

	klog.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			klog.Infof("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		klog.V(1).Info("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(parts[0])
	if err != nil {
		klog.Errorf("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	klog.Infof("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}
