package tls_client

import (
	"context"
	_tls "crypto/tls"
	"errors"
	"fmt"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const DefaultDialRetries = 3
const DebugDumpSslKeysFilename string = ""

type HttpClientCreate func(userAgent string, proxyUrl *url.URL, newConnFunc NewConnFunc, opts Options) (*http.Client, error)
type NewConnFunc func(network, addr, proto string, proxy *url.URL)
type NewClientFunc func(proto string, proxy *url.URL)

type ClientSetup struct {
	CreateClientFunc HttpClientCreate
	Options          Options
}

type clientConfig struct {
	insecureSkipVerify       bool
	randomizeHeaderOrderSeed *int64
	pseudoHeaderOrder        *[]byte
	headerOrder              *[]string
	defaultConnFlow          *uint32
	initialSettings          *[]http2.Setting
	initialSettingsToSend    *[]http2.SettingID
	priorityFrames           *map[uint32]http2.PriorityParam
	tlsSpec                  TlsSpec
}

//goland:noinspection GoUnusedExportedFunction
func Http2Client(opts ...Option) *ClientSetup {
	return &ClientSetup{
		Options: opts,
		CreateClientFunc: func(userAgent string, proxyUrl *url.URL, newConnFunc NewConnFunc, extraOptions Options) (*http.Client, error) {
			cfg, err := makeClientConfig(userAgent, append(opts, extraOptions...))
			if err != nil {
				return nil, err
			}

			trans := http2.Transport{
				DialTLSContext: func(ctx context.Context, network, addr string, _ *_tls.Config) (net.Conn, error) {
					if network != "tcp" {
						return nil, fmt.Errorf("unsupported network: %s", network)
					}

					hostname, port := getHostnameAndPort(addr)
					http2Supported, conn, err := dialRetry(hostname, port, proxyUrl, true, cfg)
					if err != nil {
						return nil, fmt.Errorf("failed opening dial for %s: %w", addr, err)
					}

					if !http2Supported {
						return nil, fmt.Errorf("http2 not supported by endpoint")
					}

					if newConnFunc != nil {
						newConnFunc(network, addr, "h2", proxyUrl)
					}

					return conn, nil
				},
				DisableCompression:         true,
				StrictMaxConcurrentStreams: false,
			}

			if cfg.defaultConnFlow != nil {
				trans.DefaultConnFlow = *cfg.defaultConnFlow
			}
			if cfg.initialSettings != nil {
				trans.InitialSettings = *cfg.initialSettings
			}
			if cfg.headerOrder != nil {
				trans.HeaderOrder = *cfg.headerOrder
			}
			if cfg.pseudoHeaderOrder != nil {
				trans.PseudoHeaderOrder = *cfg.pseudoHeaderOrder
			}
			if cfg.priorityFrames != nil {
				trans.PriorityFrames = *cfg.priorityFrames
			}
			if cfg.initialSettingsToSend != nil {
				trans.InitialSettingsToSend = *cfg.initialSettingsToSend
			}

			return &http.Client{Transport: &trans}, nil
		},
	}
}

//goland:noinspection GoUnusedExportedFunction
func Http1Client(opts ...Option) *ClientSetup {
	return &ClientSetup{
		Options: opts,
		CreateClientFunc: func(userAgent string, proxyUrl *url.URL, newConnFunc NewConnFunc, extraOptions Options) (*http.Client, error) {
			cfg, err := makeClientConfig(userAgent, append(opts, extraOptions...))
			if err != nil {
				return nil, err
			}

			// The HTTP1 client does not follow the header order specified

			return &http.Client{
				Transport: &http.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						if network != "tcp" {
							return nil, fmt.Errorf("unsupported network: %s", network)
						}

						hostname, port := getHostnameAndPort(addr)
						_, conn, err := dialRetry(hostname, port, proxyUrl, false, cfg)
						if err != nil {
							return nil, fmt.Errorf("failed opening dial for %s: %w", addr, err)
						}

						if newConnFunc != nil {
							newConnFunc(network, addr, "http/1.1", proxyUrl)
						}

						return conn, nil
					},
					DisableCompression:  true,
					DisableKeepAlives:   false,
					MaxIdleConns:        0,
					MaxConnsPerHost:     0,
					MaxIdleConnsPerHost: 1000,
					IdleConnTimeout:     0,
				},
			}, nil
		},
	}
}

var debugDumpSslKeysFile *os.File

func init() {
	if len(DebugDumpSslKeysFilename) > 0 {
		var err error
		debugDumpSslKeysFile, err = os.OpenFile(DebugDumpSslKeysFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
		if err != nil {
			panic(err)
		}
	}
}

func dialRetry(hostname string, port int, proxyUrl *url.URL, http2 bool, cfg *clientConfig) (bool, net.Conn, error) {
	var lastErr error
	for i := 0; i < DefaultDialRetries; i++ {
		http2Supported, conn, err := dial(hostname, port, proxyUrl, http2, cfg)
		if err == nil {
			return http2Supported, conn, nil
		}

		lastErr = err
		if err != io.ErrUnexpectedEOF && err != io.EOF {
			return false, nil, err
		}
	}

	return false, nil, lastErr
}

func dial(hostname string, port int, proxyUrl *url.URL, http2 bool, cfg *clientConfig) (_ bool, _ net.Conn, err error) {
	var dialer proxy.Dialer
	if proxyUrl != nil {
		if dialer, err = proxy.FromURL(proxyUrl, &net.Dialer{}); err != nil {
			return false, nil, err
		}
	} else {
		dialer = &net.Dialer{}
	}

	dial, err := dialer.Dial("tcp", hostname+":"+strconv.Itoa(port))
	if err != nil {
		return false, nil, err
	}

	config := tls.Config{ServerName: hostname, InsecureSkipVerify: cfg.insecureSkipVerify}
	if debugDumpSslKeysFile != nil {
		config.KeyLogWriter = debugDumpSslKeysFile
	}

	uTLSConn := tls.UClient(dial, &config, tls.HelloCustom)

	var alpnProtocols []string
	if http2 {
		alpnProtocols = []string{"h2", "http/1.1"}
	} else {
		alpnProtocols = []string{"http/1.1"}
	}

	var spec *tls.ClientHelloSpec
	switch cfg.tlsSpec {
	case TlsSpecFirefox93:
		spec = tlsSpecFirefox93(alpnProtocols)
		break
	case TlsSpecFirefox89:
		spec = tlsSpecFirefox89(alpnProtocols)
		break
	case TlsSpecChrome102:
		spec = tlsSpecChrome102(alpnProtocols)
		break
	case TlsSpecChrome93:
		spec = tlsSpecChrome93(alpnProtocols)
		break
	case TlsSpecSafari605:
		spec = tlsSpecSafari605(alpnProtocols)
		break
	case TlsSpecSafari604:
		spec = tlsSpecSafari604(alpnProtocols)
		break
	default:
		return false, nil, errors.New("unknown tls spec")
	}

	if err = uTLSConn.ApplyPreset(spec); err != nil {
		return false, nil, err
	} else if err = uTLSConn.Handshake(); err != nil {
		return false, nil, err
	}

	return http2 && uTLSConn.ConnectionState().NegotiatedProtocol == "h2", uTLSConn, nil
}

func getHostnameAndPort(addr string) (string, int) {
	split := strings.Split(addr, ":")
	if len(split) == 1 {
		return split[0], 80
	} else {
		port, err := strconv.Atoi(split[1])
		if err != nil {
			port = 80
		}

		return split[0], port
	}
}
