package tls_client

import (
	"fmt"
	"golang.org/x/net/http2"
	"strings"
)

type TlsSpec uint

const (
	TlsSpecFirefox93 = iota
	TlsSpecFirefox89
	TlsSpecChrome102
	TlsSpecChrome93
	TlsSpecSafari605
	TlsSpecSafari604
)

type Browser uint

const (
	BrowserEdge = iota
	BrowserOpera
	BrowserInternetExplorer
	BrowserFirefox
	BrowserChrome
	BrowserSafari
	BrowserUnknown
)

func (b Browser) Name() string {
	switch b {
	case BrowserEdge:
		return "Edge"
	case BrowserOpera:
		return "Opera"
	case BrowserInternetExplorer:
		return "IE"
	case BrowserFirefox:
		return "Firefox"
	case BrowserChrome:
		return "Chrome"
	case BrowserSafari:
		return "Safari"
	case BrowserUnknown:
		return "Unknown"
	default:
		panic(fmt.Sprintf("unknown browser name for %d", b))
	}
}

func GetBrowserFromUserAgent(userAgent string) Browser {
	if strings.Contains(userAgent, "Edge") || strings.Contains(userAgent, "EdgA") {
		return BrowserEdge
	} else if strings.Contains(userAgent, "OPR") || strings.Contains(userAgent, "Opera") {
		return BrowserOpera
	} else if strings.Contains(userAgent, "MSIE") || strings.Contains(userAgent, "Trident") {
		return BrowserInternetExplorer
	} else if strings.Contains(userAgent, "Firefox") {
		return BrowserFirefox
	} else if strings.Contains(userAgent, "Chrome") {
		return BrowserChrome
	} else if strings.Contains(userAgent, "Safari") {
		return BrowserSafari
	} else {
		return BrowserUnknown
	}
}

type BrowserSpec interface {
	getTlsSpec(userAgent string) (TlsSpec, error)
	getPseudoHeaderOrder(userAgent string) ([]byte, error)
	getHeaderOrder(userAgent string) ([]string, error)
	getInitialSettings(userAgent string) ([]http2.Setting, error)
	getDefaultConnFlow(userAgent string) (uint32, error)
	getPriorityFrames(userAgent string) (map[uint32]http2.PriorityParam, error)
	getInitialSettingsToSend(userAgent string) ([]http2.SettingID, error)
	setBrowserSpecifHeaders(userAgent string, headers *Headers, intent RequestIntent, opts Options) error
}

func getSpecForBrowser(browser Browser) BrowserSpec {
	switch browser {
	case BrowserFirefox:
		return FirefoxSpec
	case BrowserChrome:
		return ChromeSpec
	case BrowserSafari:
		return SafariSpec
	default:
		return FirefoxSpec
	}
}
