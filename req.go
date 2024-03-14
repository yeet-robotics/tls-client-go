package tls_client

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/andybalholm/brotli"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"time"
)

var ErrTooManyRedirects = errors.New("too many redirects")

type RequestIntent int

const (
	RequestIntentNone RequestIntent = iota
	RequestIntentNavigate
	RequestIntentEmptyCrossSiteNoCors
	RequestIntentEmptyCrossSiteCors
	RequestIntentEmptySameSiteCors
	RequestIntentEmptySameOriginCors
	RequestIntentScriptSameOriginNoCors
	RequestIntentScriptSameSiteCors
)

type Request struct {
	RequestUrl           *url.URL
	ProxyUrl             *url.URL
	Method               string
	Headers              *Headers
	Body                 []byte
	Timeout              int
	CookieJar            *cookiejar.Jar
	FollowRedirect       bool
	MaxTries             int
	RetryFunc            func(*Request, *http.Response, error) *Request
	NewClientFunc        HttpClientCreate
	NewClientCreatedFunc NewClientFunc
	Decompress           bool
	Intent               RequestIntent

	Client *http.Client

	// response The previous hop
	response      *http.Response
	redirectCount int
	tries         int
	browser       Browser
}

// redirectBehavior Taken from the Golang source code
func redirectBehavior(reqMethod string, resp *http.Response) (redirectMethod string, shouldRedirect, includeBody bool) {
	switch resp.StatusCode {
	case 301, 302, 303:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = false
		if reqMethod != "GET" && reqMethod != "HEAD" {
			redirectMethod = "GET"
		}
	case 307, 308:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = true
		if resp.Header.Get("Location") == "" {
			shouldRedirect = false
			break
		}
	}
	return redirectMethod, shouldRedirect, includeBody
}

func (c *ClientsPool) Do(ctx context.Context, req *Request, opts ...Option) (*http.Client, *http.Response, error) {
	if req.Headers == nil {
		req.Headers = &Headers{}
	}

	altClient := Options(opts).FindBoolOption(OptionUseAltClient, false)

	if req.MaxTries == 0 {
		req.MaxTries = c.config.MaxTries
	}
	if req.RetryFunc == nil {
		req.RetryFunc = c.config.RetryFunc
	}
	if req.NewClientFunc == nil {
		if altClient {
			if c.config.AltClient == nil {
				return nil, nil, errors.New("no alt client provided")
			}

			req.NewClientFunc = c.config.AltClient.CreateClientFunc
		} else {
			req.NewClientFunc = c.config.Client.CreateClientFunc
		}
	}
	if req.NewClientCreatedFunc == nil {
		req.NewClientCreatedFunc = c.config.NewClientCreatedFunc
	}

	// Set browser specific headers
	userAgent, _ := req.Headers.GetFirst("User-Agent")
	req.browser = GetBrowserFromUserAgent(userAgent)

	if err := getSpecForBrowser(req.browser).setBrowserSpecifHeaders(userAgent, req.Headers, req.Intent, opts); err != nil {
		return nil, nil, err
	}

	// Prepare request
	var bodyReader *bytes.Reader
	if len(req.Body) > 0 {
		req.Headers.Set("Content-Length", strconv.Itoa(len(req.Body)))
		bodyReader = bytes.NewReader(req.Body)

		if req.Method == "" {
			req.Method = "POST"
		}
	} else {
		bodyReader = bytes.NewReader(make([]byte, 0))

		if req.Method == "" {
			req.Method = "GET"
		}
	}

	originalCtx := ctx
	if req.Timeout != 0 {
		ctx, _ = context.WithTimeout(ctx, time.Duration(req.Timeout)*time.Millisecond)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.RequestUrl.String(), bodyReader)
	if err != nil {
		return nil, nil, err
	}

	// Hack in the previous hop response
	httpReq.Response = req.response

	httpReq.Header.Set("Host", req.RequestUrl.Host)

	var headerOrder []string
	if altClient {
		headerOrder = c.config.AltClient.Options.FindStringSliceOption(OptionHeaderOrder)
	} else {
		headerOrder = c.config.Client.Options.FindStringSliceOption(OptionHeaderOrder)
	}

	req.Headers.AddToRequest(httpReq, headerOrder)

	if val, ok := req.Headers.GetFirst("Connection"); ok && val == "close" {
		httpReq.Close = true
	} else {
		req.Headers.Set("Connection", "keep-alive")
		httpReq.Close = false
	}

	if req.CookieJar != nil {
		for _, cookie := range req.CookieJar.Cookies(req.RequestUrl) {
			httpReq.AddCookie(cookie)
		}
	}

	var httpClient *http.Client
	if req.Client != nil {
		httpClient = req.Client
	} else {
		var created bool
		httpClient, created, err = c.ComputeIfAbsent(userAgent, req.ProxyUrl, req.NewClientFunc, opts)
		if err != nil {
			return nil, nil, err
		}

		req.Client = httpClient

		// If the client has just been created call the func
		if created && req.NewClientCreatedFunc != nil {
			var proto string
			_, ok := httpClient.Transport.(*http.Transport)
			if ok {
				proto = "http/1.1"
			} else {
				_, ok = httpClient.Transport.(*http2.Transport)
				if ok {
					proto = "h2"
				} else {
					proto = "unknown"
				}
			}

			req.NewClientCreatedFunc(proto, req.ProxyUrl)
		}
	}

	// Send the request
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		if req.RetryFunc != nil && req.tries < req.MaxTries {
			if retryReq := req.RetryFunc(req, nil, err); retryReq != nil {
				retryReq.tries = req.tries + 1
				return c.Do(originalCtx, retryReq, opts...)
			}
		}

		return httpClient, nil, err
	}

	if req.CookieJar != nil {
		req.CookieJar.SetCookies(&url.URL{
			Scheme: httpResp.Request.URL.Scheme,
			Host:   httpResp.Request.URL.Host,
			Path:   "/",
		}, httpResp.Cookies())
	}

	if req.RetryFunc != nil && req.tries < req.MaxTries {
		if retryReq := req.RetryFunc(req, httpResp, nil); retryReq != nil {
			retryReq.tries = req.tries + 1
			return c.Do(originalCtx, retryReq, opts...)
		}
	}

	if httpResp.StatusCode >= 300 && httpResp.StatusCode <= 399 && req.FollowRedirect {
		redirectMethod, shouldRedirect, includeBody := redirectBehavior(req.Method, httpResp)
		if !shouldRedirect {
			return httpClient, httpResp, nil
		}

		req.redirectCount++
		if req.redirectCount > 10 {
			return httpClient, nil, ErrTooManyRedirects
		}

		loc, err := httpResp.Location()
		if err != nil {
			return httpClient, nil, errors.New("missing redirect location")
		}

		var newBody []byte
		if includeBody {
			newBody = req.Body
		}

		return c.Do(originalCtx, &Request{
			RequestUrl:           loc,
			ProxyUrl:             req.ProxyUrl,
			Method:               redirectMethod,
			Headers:              req.Headers,
			Body:                 newBody,
			Timeout:              req.Timeout,
			CookieJar:            req.CookieJar,
			FollowRedirect:       req.FollowRedirect,
			MaxTries:             req.MaxTries,
			RetryFunc:            req.RetryFunc,
			NewClientFunc:        req.NewClientFunc,
			NewClientCreatedFunc: req.NewClientCreatedFunc,
			Decompress:           req.Decompress,
			response:             httpResp,
			redirectCount:        req.redirectCount,
			Client:               httpClient,
		}, opts...)
	}

	if req.Decompress {
		err := Decompress(httpResp)
		if err != nil {
			return nil, nil, err
		}
	}

	return httpClient, httpResp, nil
}

func Decompress(resp *http.Response) error {
	if resp.Uncompressed {
		return nil
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding == "" {
		return nil
	}

	decompressed, err := DecompressReader(resp.Body, contentEncoding)
	if err != nil {
		return err
	}

	resp.Body = decompressed
	resp.ContentLength = -1
	resp.Uncompressed = true
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	return nil
}

func DecompressReader(reader io.Reader, encoding string) (out io.ReadCloser, err error) {
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}

		return io.NopCloser(reader), nil
	case "br":
		return io.NopCloser(brotli.NewReader(reader)), nil
	case "deflate":
		return flate.NewReader(reader), nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}
