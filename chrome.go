package tls_client

import (
	"fmt"
	"github.com/elliotchance/pie/v2"
	tls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"math/rand"
	"strconv"
	"strings"
)

var ChromeSpec BrowserSpec

type chromeSpec struct {
	defaultConnFlow   uint32
	headerOrder       []string
	pseudoHeaderOrder []byte
}

func (s chromeSpec) getTlsSpec(_ string) (TlsSpec, error) {
	return TlsSpecChrome102, nil
}

func (s chromeSpec) getPseudoHeaderOrder(_ string) ([]byte, error) {
	return s.pseudoHeaderOrder, nil
}

func (s chromeSpec) getHeaderOrder(_ string) ([]string, error) {
	return s.headerOrder, nil
}

func (s chromeSpec) getInitialSettings(userAgent string) ([]http2.Setting, error) {
	majorVersion := ChromeMajorVersion(userAgent)
	if majorVersion == 0 {
		return nil, fmt.Errorf("cannot extract chrome version from %s", userAgent)
	}

	if majorVersion < 106 {
		return []http2.Setting{
			{http2.SettingHeaderTableSize, 65536},
			{http2.SettingMaxConcurrentStreams, 1000},
			{http2.SettingInitialWindowSize, 6291456},
			{http2.SettingMaxHeaderListSize, 262144},
		}, nil
	} else {
		return []http2.Setting{
			{http2.SettingHeaderTableSize, 65536},
			{http2.SettingEnablePush, 0},
			{http2.SettingMaxConcurrentStreams, 1000},
			{http2.SettingInitialWindowSize, 6291456},
			{http2.SettingMaxHeaderListSize, 262144},
		}, nil
	}
}

func (s chromeSpec) getDefaultConnFlow(_ string) (uint32, error) {
	return s.defaultConnFlow, nil
}

func (s chromeSpec) getPriorityFrames(_ string) (map[uint32]http2.PriorityParam, error) {
	return nil, nil
}

func (s chromeSpec) getInitialSettingsToSend(userAgent string) ([]http2.SettingID, error) {
	majorVersion := ChromeMajorVersion(userAgent)
	if majorVersion == 0 {
		return nil, fmt.Errorf("cannot extract chrome version from %s", userAgent)
	}

	if majorVersion < 106 {
		return []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}, nil
	} else {
		return []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}, nil
	}
}

func (s chromeSpec) setBrowserSpecifHeaders(userAgent string, headers *Headers, intent RequestIntent, opts Options) error {
	majorVersion := ChromeMajorVersion(userAgent)
	if majorVersion == 0 {
		return fmt.Errorf("cannot extract chrome version from %s", userAgent)
	}

	if !headers.Has("Accept-Language") {
		languages := opts.FindStringSliceOption(OptionLanguages)
		if len(languages) > 0 {
			headers.Set("Accept-Language", ChromeBuildAcceptLanguageHeader(languages))
		} else {
			headers.Set("Accept-Language", "en-US,en;q=0.9")
		}
	}

	headers.SetIfAbsent("Accept-Encoding", "gzip, deflate, br")
	headers.Set("Sec-Ch-Ua-Mobile", "?0")
	headers.Set("Sec-Ch-Ua", func(secChUa [][]string) string {
		greased := make([]string, 3)
		for i := 0; i < 3; i++ {
			greased[i] = fmt.Sprintf("\"%s\";v=\"%s\"", secChUa[i][0], secChUa[i][1])
		}
		return strings.Join(greased, ", ")
	}(ChromeSecChUa(majorVersion)))

	if strings.Contains(userAgent, "Win64") {
		headers.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	} else if strings.Contains(userAgent, "X11") {
		headers.Set("Sec-Ch-Ua-Platform", "\"Linux\"")
	} else if strings.Contains(userAgent, "Mac") {
		headers.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
	}

	switch intent {
	case RequestIntentNavigate:
		headers.SetIfAbsent("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
		headers.Set("Upgrade-Insecure-Requests", "1")
		headers.SetIfAbsent("Sec-Fetch-Dest", "document")
		headers.SetIfAbsent("Sec-Fetch-Site", "none")
		headers.SetIfAbsent("Sec-Fetch-Mode", "navigate")
		headers.SetIfAbsent("Sec-Fetch-User", "?1")
	case RequestIntentEmptyCrossSiteNoCors:
		headers.SetIfAbsent("Accept", "*/*")
		headers.SetIfAbsent("Sec-Fetch-Dest", "empty")
		headers.SetIfAbsent("Sec-Fetch-Site", "cross-site")
		headers.SetIfAbsent("Sec-Fetch-Mode", "no-cors")
	case RequestIntentEmptyCrossSiteCors:
		headers.SetIfAbsent("Accept", "*/*")
		headers.SetIfAbsent("Sec-Fetch-Dest", "empty")
		headers.SetIfAbsent("Sec-Fetch-Site", "cross-site")
		headers.SetIfAbsent("Sec-Fetch-Mode", "cors")
	case RequestIntentScriptSameOriginNoCors:
		headers.SetIfAbsent("Accept", "*/*")
		headers.SetIfAbsent("Sec-Fetch-Dest", "script")
		headers.SetIfAbsent("Sec-Fetch-Site", "same-origin")
		headers.SetIfAbsent("Sec-Fetch-Mode", "no-cors")
	case RequestIntentScriptSameSiteCors:
		headers.SetIfAbsent("Accept", "*/*")
		headers.SetIfAbsent("Sec-Fetch-Dest", "script")
		headers.SetIfAbsent("Sec-Fetch-Site", "same-site")
		headers.SetIfAbsent("Sec-Fetch-Mode", "cors")
	case RequestIntentEmptySameSiteCors:
		headers.SetIfAbsent("Accept", "*/*")
		headers.SetIfAbsent("Sec-Fetch-Dest", "empty")
		headers.SetIfAbsent("Sec-Fetch-Site", "same-site")
		headers.SetIfAbsent("Sec-Fetch-Mode", "cors")
	case RequestIntentEmptySameOriginCors:
		headers.SetIfAbsent("Accept", "*/*")
		headers.SetIfAbsent("Sec-Fetch-Dest", "empty")
		headers.SetIfAbsent("Sec-Fetch-Site", "same-origin")
		headers.SetIfAbsent("Sec-Fetch-Mode", "cors")
	case RequestIntentNone:
	default:
		return fmt.Errorf("unknown intent: %d", intent)
	}

	return nil
}

func init() {
	ChromeSpec = chromeSpec{
		defaultConnFlow: 15663105,
		headerOrder: []string{"Host", "Content-Length", "Sec-Ch-Ua", "Accept", "Upgrade-Insecure-Requests",
			"Sec-Ch-Ua-Mobile", "User-Agent", "Sec-Ch-Ua-Platform", "Content-Type", "Origin", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language", "Cookie", "TE"},
		pseudoHeaderOrder: []byte{'m', 'a', 's', 'p'},
	}
}

func ChromeBuildAcceptLanguageHeader(languages []string) string {
	// https://source.chromium.org/chromium/chromium/src/+/main:net/http/http_util.cc;l=716;drc=f97e7e130b02a0fee5a06aa9cdf25d3a0a3715d0;bpv=0;bpt=1
	qValue := 10
	var list strings.Builder
	for _, lang := range languages {
		if qValue == 10 {
			list.WriteString(lang)
		} else {
			list.WriteString(fmt.Sprintf(",%s;q=0.%d", lang, qValue))
		}
		if qValue > 1 {
			qValue -= 1
		}
	}

	return list.String()
}

func ChromeRandomFullVersionFromMajor(majorVersion int) string {
	// https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions
	var fullVersions = map[int][]string{
		112: {"112.0.5615.49"},
		111: {"111.0.5563.148", "111.0.5563.147", "111.0.5563.146", "111.0.5563.112", "111.0.5563.111", "111.0.5563.110", "111.0.5563.66", "111.0.5563.65", "111.0.5563.64", "111.0.5563.64", "111.0.5563.50"},
		110: {"110.0.5481.180", "110.0.5481.180", "110.0.5481.179", "110.0.5481.178", "110.0.5481.177", "110.0.5481.105", "110.0.5481.104", "110.0.5481.100", "110.0.5481.97", "110.0.5481.96", "110.0.5481.78", "110.0.5481.77", "110.0.5481.77"},
		109: {"109.0.5414.122", "109.0.5414.121", "109.0.5414.121", "109.0.5414.120", "109.0.5414.119", "109.0.5414.76", "109.0.5414.75", "109.0.5414.74"},
		108: {"108.0.5359.125", "108.0.5359.124", "108.0.5359.100", "108.0.5359.99", "108.0.5359.98", "108.0.5359.96", "108.0.5359.95", "108.0.5359.94", "108.0.5359.73", "108.0.5359.72", "108.0.5359.71"},
		107: {"107.0.5304.123", "107.0.5304.122", "107.0.5304.121", "107.0.5304.108", "107.0.5304.107", "107.0.5304.106", "107.0.5304.89", "107.0.5304.88", "107.0.5304.87", "107.0.5304.63", "107.0.5304.62"},
		106: {"106.0.5249.121", "106.0.5249.120", "106.0.5249.119", "106.0.5249.103", "106.0.5249.91", "106.0.5249.62", "106.0.5249.61"},
		105: {"105.0.5195.127", "105.0.5195.126", "105.0.5195.125", "105.0.5195.102", "105.0.5195.54", "105.0.5195.53", "105.0.5195.52"},
		104: {"104.0.5112.102", "104.0.5112.101", "104.0.5112.82", "104.0.5112.81", "104.0.5112.80", "104.0.5112.79"},
		103: {"103.0.5060.134", "103.0.5060.114", "103.0.5060.66", "103.0.5060.53"},
		102: {"102.0.5005.115", "102.0.5005.63", "102.0.5005.62", "102.0.5005.61"},
		101: {"101.0.4951.67", "101.0.4951.64", "101.0.4951.54", "101.0.4951.41"},
		100: {"100.0.4896.127", "100.0.4896.88", "100.0.4896.75", "100.0.4896.60"},
		99:  {"99.0.4844.84", "99.0.4844.82", "99.0.4844.74", "99.0.4844.51"},
	}

	majorGroup, ok := fullVersions[majorVersion]
	if !ok {
		log.Warnf("unknown chrome major version %d", majorVersion)
		return ""
	}

	return majorGroup[rand.Intn(len(majorGroup))]
}

func ChromeSecChUa(majorVersion int) [][]string {
	// https://source.chromium.org/chromium/chromium/src/+/main:components/embedder_support/user_agent_utils.cc;drc=f97e7e130b02a0fee5a06aa9cdf25d3a0a3715d0;l=529

	var greasyChars = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	var greasyVersion = []string{"8", "99", "24"}
	var greasyOrders = [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}

	order := greasyOrders[majorVersion%len(greasyOrders)]

	greased := make([][]string, 3)
	greased[order[0]] = []string{fmt.Sprintf("Not%sA%sBrand", greasyChars[(majorVersion%len(greasyChars))], greasyChars[(majorVersion+1)%len(greasyChars)]), greasyVersion[majorVersion%len(greasyVersion)]}
	greased[order[1]] = []string{"Chromium", strconv.Itoa(majorVersion)}
	greased[order[2]] = []string{"Google Chrome", strconv.Itoa(majorVersion)}
	return greased
}

func ChromeMajorVersion(ua string) int {
	versionStart := strings.Index(ua, "Chrome/")
	if versionStart >= 0 {
		versionStart += 7

		versionEnd := strings.Index(ua[versionStart:], ".")
		if versionEnd >= 0 {
			versionEnd += versionStart
			versionInt, _ := strconv.Atoi(ua[versionStart:versionEnd])
			return versionInt
		}
	}

	return 0
}

// 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
func tlsSpecChrome102(alpn []string) *tls.ClientHelloSpec {
	var alps []string
	if pie.Contains(alpn, "h2") {
		alps = append(alps, "h2")
	}

	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS10,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.GREASE_PLACEHOLDER,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: alpn},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.GenericExtension{Id: 0x12}, // signed_certificate_timestamp
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0x00}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.CertCompressionAlgsExtension{Methods: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
			&tls.ALPSExtension{SupportedProtocols: alps},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}}
}

// 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0
func tlsSpecChrome93(alpn []string) *tls.ClientHelloSpec {
	var alps []string
	if pie.Contains(alpn, "h2") {
		alps = append(alps, "h2")
	}

	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS10,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.GREASE_PLACEHOLDER,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: alpn},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.GenericExtension{Id: 0x12}, // signed_certificate_timestamp
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0x00}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10,
			}},
			&tls.CertCompressionAlgsExtension{Methods: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
			&tls.ALPSExtension{SupportedProtocols: alps},
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}}
}
