package tls_client

import (
	"fmt"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var FirefoxSpec BrowserSpec

type firefoxSpec struct {
	initialSettings       []http2.Setting
	defaultConnFlow       uint32
	initialSettingsToSend []http2.SettingID
	headerOrder           []string
	pseudoHeaderOrder     []byte
	priorityFrames        map[uint32]http2.PriorityParam
}

func (s firefoxSpec) getTlsSpec(_ string) (TlsSpec, error) {
	return TlsSpecFirefox93, nil
}

func (s firefoxSpec) getPseudoHeaderOrder(_ string) ([]byte, error) {
	return s.pseudoHeaderOrder, nil
}

func (s firefoxSpec) getHeaderOrder(_ string) ([]string, error) {
	return s.headerOrder, nil
}

func (s firefoxSpec) getInitialSettings(_ string) ([]http2.Setting, error) {
	return s.initialSettings, nil
}

func (s firefoxSpec) getDefaultConnFlow(_ string) (uint32, error) {
	return s.defaultConnFlow, nil
}

func (s firefoxSpec) getPriorityFrames(_ string) (map[uint32]http2.PriorityParam, error) {
	return s.priorityFrames, nil
}

func (s firefoxSpec) getInitialSettingsToSend(_ string) ([]http2.SettingID, error) {
	return s.initialSettingsToSend, nil
}

func (s firefoxSpec) setBrowserSpecifHeaders(_ string, headers *Headers, intent RequestIntent, _ Options) error {
	headers.SetIfAbsent("Accept-Language", "en-US,en;q=0.5")
	headers.SetIfAbsent("Accept-Encoding", "gzip, deflate, br")
	headers.Set("TE", "trailers")

	switch intent {
	case RequestIntentNavigate:
		headers.SetIfAbsent("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
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
	FirefoxSpec = firefoxSpec{
		initialSettings: []http2.Setting{
			{http2.SettingHeaderTableSize, 65536},
			{http2.SettingInitialWindowSize, 131072},
			{http2.SettingMaxFrameSize, 16384},
		},
		defaultConnFlow:       12517377,
		initialSettingsToSend: []http2.SettingID{http2.SettingHeaderTableSize, http2.SettingInitialWindowSize, http2.SettingMaxFrameSize},
		headerOrder: []string{"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer",
			"Content-Type", "Content-Length", "Origin", "DNT", "Connection", "Cookie", "Upgrade-Insecure-Requests",
			"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Cache-Control", "TE"},
		pseudoHeaderOrder: []byte{'m', 'p', 'a', 's'},
		priorityFrames: map[uint32]http2.PriorityParam{
			3:  {StreamDep: 0, Exclusive: false, Weight: 200},
			5:  {StreamDep: 0, Exclusive: false, Weight: 100},
			7:  {StreamDep: 0, Exclusive: false, Weight: 0},
			9:  {StreamDep: 7, Exclusive: false, Weight: 0},
			11: {StreamDep: 3, Exclusive: false, Weight: 0},
			13: {StreamDep: 0, Exclusive: false, Weight: 240},
		},
	}
}

// 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0
func tlsSpecFirefox93(alpnProtocols []string) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS10,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				tls.CurveID(tls.FakeFFDHE2048),
				tls.CurveID(tls.FakeFFDHE3072),
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: alpnProtocols},
			&tls.StatusRequestExtension{},
			&tls.GenericExtension{Id: 34, Data: []byte{0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03}}, // delegated_credentials
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519},
				{Group: tls.CurveP256},
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}}
}

// 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0
func tlsSpecFirefox89(alpnProtocols []string) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS10,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				tls.CurveID(tls.FakeFFDHE2048),
				tls.CurveID(tls.FakeFFDHE3072),
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: alpnProtocols},
			&tls.StatusRequestExtension{},
			&tls.GenericExtension{Id: 34, Data: []byte{0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03}}, // delegated_credentials
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519},
				{Group: tls.CurveP256},
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}}
}
