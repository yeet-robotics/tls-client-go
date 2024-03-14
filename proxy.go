package tls_client

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

type ProxyError struct {
	StatusCode int
	error      error
}

func (e *ProxyError) Error() string {
	return e.error.Error()
}

type httpProxy struct {
	host    string
	port    int
	forward proxy.Dialer

	hasAuth  bool
	username string
	password string
}

func getPortFor(url *url.URL) (int, error) {
	portStr := url.Port()
	if len(portStr) == 0 {
		if url.Scheme == "https" {
			return 443, nil
		} else if url.Scheme == "http" {
			return 80, nil
		} else {
			return 0, errors.New("invalid scheme: " + url.Scheme)
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}

	return port, nil
}

func makeHttpProxy(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	port, err := getPortFor(uri)
	if err != nil {
		return nil, err
	}

	s := new(httpProxy)
	s.host = uri.Hostname()
	s.port = port
	s.forward = forward
	if uri.User != nil {
		s.hasAuth = true
		s.username = uri.User.Username()
		s.password, _ = uri.User.Password()
	}

	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("unsupported network: " + network)
	}

	conn, err := s.forward.Dial("tcp", s.host+":"+strconv.Itoa(s.port))
	if err != nil {
		return nil, &ProxyError{0, err}
	}

	proxyAddr, err := url.Parse("http://" + addr)
	if err != nil {
		_ = conn.Close()
		return nil, &ProxyError{0, err}
	}
	proxyAddr.Scheme = ""

	proxyReq, err := http.NewRequest("CONNECT", proxyAddr.String(), nil)
	if err != nil {
		_ = conn.Close()
		return nil, &ProxyError{0, err}
	}

	proxyReq.Header.Add("Host", addr)
	proxyReq.Close = false
	if s.hasAuth {
		auth := base64.StdEncoding.EncodeToString([]byte(s.username + ":" + s.password))
		proxyReq.Header.Add("Proxy-Authorization", "Basic "+auth)
	}

	if err = proxyReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, &ProxyError{0, err}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), proxyReq)
	if err != nil {
		_ = conn.Close()
		return nil, &ProxyError{0, err}
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, &ProxyError{
			error:      fmt.Errorf("failed connecting to server with proxy, status code: %d", resp.StatusCode),
			StatusCode: resp.StatusCode,
		}
	}

	return conn, nil
}

func init() {
	proxy.RegisterDialerType("http", makeHttpProxy)
	proxy.RegisterDialerType("https", makeHttpProxy)
}
