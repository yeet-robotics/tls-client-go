package tls_client

import (
	"context"
	"golang.org/x/net/http2"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type ClientsPool struct {
	cleanup *time.Ticker
	clients *sync.Map
	config  *PoolConfig
	close   chan bool
}

type PoolConfig struct {
	MaxTries             int
	RetryFunc            func(*Request, *http.Response, error) *Request
	Client               *ClientSetup
	AltClient            *ClientSetup
	NewClientCreatedFunc NewClientFunc
	NewConnCreatedFunc   NewConnFunc
}

const DefaultMaxTries = 10

func NewPool() *ClientsPool {
	pool := &ClientsPool{
		clients: &sync.Map{},
		cleanup: time.NewTicker(30 * time.Minute),
		close:   make(chan bool),
		config: &PoolConfig{
			MaxTries: DefaultMaxTries,
		},
	}

	go func() {
		select {
		case <-pool.close:
			return
		case <-pool.cleanup.C:
			pool.clients.Range(func(key, value interface{}) bool {
				value.(*http.Client).CloseIdleConnections()
				return true
			})
		}
	}()

	return pool
}

func (c *ClientsPool) Config(config *PoolConfig) {
	c.config = config

	if config.Client == nil {
		panic("missing client")
	}
}

func (c *ClientsPool) Shutdown() {
	c.cleanup.Stop()
	c.close <- true

	c.clients.Range(func(key, value interface{}) bool {
		shutdownClient(value.(*http.Client))
		c.clients.Delete(key)
		return true
	})
}

func makeClientFromProxy(proxy *url.URL) string {
	clientId := proxy.Host
	if proxy.User != nil {
		clientId += proxy.User.Username()
	}
	return clientId
}

func (c *ClientsPool) ComputeIfAbsent(userAgent string, proxyUrl *url.URL, createClient HttpClientCreate, opts Options) (*http.Client, bool, error) {
	var clientId string
	if proxyUrl != nil {
		clientId = makeClientFromProxy(proxyUrl)
	} else {
		clientId = userAgent
	}

	if client, ok := c.clients.Load(clientId); ok {
		return client.(*http.Client), false, nil
	}

	client, err := createClient(userAgent, proxyUrl, c.config.NewConnCreatedFunc, opts)
	if err != nil {
		return nil, false, err
	}

	client.Timeout = 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	if opts.FindBoolOption(OptionCacheClient, true) {
		c.clients.Store(clientId, client)
	}

	return client, true, nil
}

func (c *ClientsPool) Invalidate(proxyUrl *url.URL) {
	clientId := makeClientFromProxy(proxyUrl)

	client, ok := c.clients.Load(clientId)
	if !ok {
		return
	}

	c.clients.Delete(clientId)
	shutdownClient(client.(*http.Client))
}

func shutdownClient(client *http.Client) {
	// Close clients when unlocked because this could take a bit
	if h2, ok := client.Transport.(*http2.Transport); ok {
		h2.GetConnPool().Shutdown(context.Background())
	} else if h1, ok := client.Transport.(*http.Transport); ok {
		h1.CloseIdleConnections() // could be better implemented
	}
}
