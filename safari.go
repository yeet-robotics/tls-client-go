package tls_client

import (
	"fmt"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var SafariSpec BrowserSpec

type safariSpec struct {
	initialSettings       []http2.Setting
	defaultConnFlow       uint32
	initialSettingsToSend []http2.SettingID
	headerOrder           []string
	pseudoHeaderOrder     []byte
}

func (s safariSpec) getTlsSpec(_ string) (TlsSpec, error) {
	return TlsSpecSafari605, nil
}

func (s safariSpec) getPseudoHeaderOrder(_ string) ([]byte, error) {
	return s.pseudoHeaderOrder, nil
}

func (s safariSpec) getHeaderOrder(_ string) ([]string, error) {
	return s.headerOrder, nil
}

func (s safariSpec) getInitialSettings(_ string) ([]http2.Setting, error) {
	return s.initialSettings, nil
}

func (s safariSpec) getDefaultConnFlow(_ string) (uint32, error) {
	return s.defaultConnFlow, nil
}

func (s safariSpec) getPriorityFrames(_ string) (map[uint32]http2.PriorityParam, error) {
	return nil, nil
}

func (s safariSpec) getInitialSettingsToSend(_ string) ([]http2.SettingID, error) {
	return s.initialSettingsToSend, nil
}

func (s safariSpec) setBrowserSpecifHeaders(_ string, headers *Headers, intent RequestIntent, _ Options) error {
	headers.SetIfAbsent("Accept-Language", "en-US")
	headers.SetIfAbsent("Accept-Encoding", "gzip, deflate, br")

	switch intent {
	case RequestIntentNavigate:
		headers.SetIfAbsent("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	case RequestIntentEmptyCrossSiteNoCors:
		headers.SetIfAbsent("Accept", "*/*")
	case RequestIntentEmptyCrossSiteCors:
		headers.SetIfAbsent("Accept", "*/*")
	case RequestIntentScriptSameOriginNoCors:
		headers.SetIfAbsent("Accept", "*/*")
	case RequestIntentScriptSameSiteCors:
		headers.SetIfAbsent("Accept", "*/*")
	case RequestIntentEmptySameSiteCors:
		headers.SetIfAbsent("Accept", "*/*")
	case RequestIntentEmptySameOriginCors:
		headers.SetIfAbsent("Accept", "*/*")
	case RequestIntentNone:
		break
	default:
		return fmt.Errorf("unknown intent: %d", intent)
	}

	return nil
}

func init() {
	SafariSpec = safariSpec{
		initialSettings: []http2.Setting{
			{http2.SettingInitialWindowSize, 4194304},
			{http2.SettingMaxConcurrentStreams, 100},
		},
		defaultConnFlow:       10485760,
		initialSettingsToSend: []http2.SettingID{http2.SettingInitialWindowSize, http2.SettingMaxConcurrentStreams},
		headerOrder: []string{"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
			"Content-Length", "Content-Type", "Origin", "Referer", "Cookie"},
		pseudoHeaderOrder: []byte{'m', 's', 'p', 'a'},
	}
}

// 771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-21,29-23-24-25,0
func tlsSpecSafari605(alpnProtocols []string) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS10,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			0xc008,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
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
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.ALPNExtension{AlpnProtocols: alpnProtocols},
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
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10,
			}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}}
}

// 771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0
func tlsSpecSafari604(alpnProtocols []string) *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS10,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			0xc008,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
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
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.ALPNExtension{AlpnProtocols: alpnProtocols},
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
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10,
			}},
			&tls.CertCompressionAlgsExtension{Methods: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		}}
}
