package tls_client

import (
	"fmt"
	"golang.org/x/exp/slices"
	"golang.org/x/net/http2"
	"math/rand"
	"reflect"
)

type OptionID string

const (
	OptionInitialSettings       OptionID = "initialSettings"
	OptionInitialSettingsToSend OptionID = "initialSettingsToSend"
	OptionInsecureSkipVerify    OptionID = "insecureSkipVerify"
	OptionDefaultConnFlow       OptionID = "defaultConnFlow"
	OptionPseudoHeaderOrder     OptionID = "pseudoHeaderOrder"
	OptionHeaderOrder           OptionID = "headerOrder"
	OptionPriorityFrames        OptionID = "priorityFrames"
	OptionRandomizeHeaderOrder  OptionID = "randomizeHeaderOrder"
	OptionTlsSpec               OptionID = "tlsSpec"
	OptionCacheClient           OptionID = "cacheClient"
	OptionUseAltClient          OptionID = "useAltClient"
	OptionLanguages             OptionID = "languages"
	OptionDisableServerPush     OptionID = "disableServerPush"
)

type Option struct {
	Name  OptionID
	Value interface{}
}

type Options []Option

func (o Options) FindOption(name OptionID) (bool, interface{}) {
	for _, opt := range o {
		if opt.Name == name {
			return true, opt.Value
		}
	}

	return false, nil
}

func (o Options) FindBoolOption(name OptionID, fallback bool) bool {
	ok, val := o.FindOption(name)
	if !ok {
		return fallback
	}

	return val.(bool)
}

func (o Options) FindStringSliceOption(name OptionID) []string {
	ok, val := o.FindOption(name)
	if !ok {
		return nil
	}

	return val.([]string)
}

func NewInitialSettingsOption(val []http2.Setting) Option {
	return Option{Name: OptionInitialSettings, Value: val}
}

func NewInitialSettingsToSendOption(val []http2.SettingID) Option {
	return Option{Name: OptionInitialSettingsToSend, Value: val}
}

func NewInsecureSkipVerifyOption(val bool) Option {
	return Option{Name: OptionInsecureSkipVerify, Value: val}
}

func NewDefaultConnFlowOption(val uint32) Option {
	return Option{Name: OptionDefaultConnFlow, Value: val}
}

func NewPseudoHeaderOrderOption(val ...byte) Option {
	return Option{Name: OptionPseudoHeaderOrder, Value: val}
}

func NewHeaderOrderOption(val ...string) Option {
	return Option{Name: OptionHeaderOrder, Value: val}
}

func NewTlsSpecOption(val TlsSpec) Option {
	return Option{Name: OptionTlsSpec, Value: val}
}

func NewPriorityFramesOption(val map[uint32]http2.PriorityParam) Option {
	return Option{Name: OptionPriorityFrames, Value: val}
}

func NewRandomizeHeaderOrderOption(seed int64) Option {
	return Option{Name: OptionRandomizeHeaderOrder, Value: seed}
}

func NewCacheClientOption(val bool) Option {
	return Option{Name: OptionCacheClient, Value: val}
}

func NewUseAltClientOption(val bool) Option {
	return Option{Name: OptionUseAltClient, Value: val}
}

func NewLanguagesOption(val []string) Option {
	return Option{Name: OptionLanguages, Value: val}
}

func NewDisableServerPush(val bool) Option {
	return Option{Name: OptionDisableServerPush, Value: val}
}

// makeClientConfig parses the given user agent and options to create a configuration for the HTTP client.
// Duplicate Options are allowed, only the latter will be considered.
func makeClientConfig(userAgent string, opts Options) (*clientConfig, error) {
	cfg := clientConfig{}

	var overrideDefaultConnFlow *uint32
	var overrideInitialSettings *[]http2.Setting
	var overrideInitialSettingsToSend *[]http2.SettingID
	var overridePseudoHeaderOrder *[]byte
	var overrideHeaderOrder *[]string
	var overridePriorityFrames *map[uint32]http2.PriorityParam
	var overrideTlsSpec *TlsSpec
	for _, opt := range opts {
		if opt.Name == OptionInitialSettings {
			val := opt.Value.([]http2.Setting)
			overrideInitialSettings = &val
		} else if opt.Name == OptionInitialSettingsToSend {
			val := opt.Value.([]http2.SettingID)
			overrideInitialSettingsToSend = &val
		} else if opt.Name == OptionDefaultConnFlow {
			val := opt.Value.(uint32)
			overrideDefaultConnFlow = &val
		} else if opt.Name == OptionPseudoHeaderOrder {
			val := opt.Value.([]byte)
			overridePseudoHeaderOrder = &val
		} else if opt.Name == OptionHeaderOrder {
			val := opt.Value.([]string)
			overrideHeaderOrder = &val
		} else if opt.Name == OptionInsecureSkipVerify {
			cfg.insecureSkipVerify = opt.Value.(bool)
		} else if opt.Name == OptionTlsSpec {
			val := opt.Value.(TlsSpec)
			overrideTlsSpec = &val
		} else if opt.Name == OptionPriorityFrames {
			val := opt.Value.(map[uint32]http2.PriorityParam)
			overridePriorityFrames = &val
		} else if opt.Name == OptionRandomizeHeaderOrder {
			val := opt.Value.(int64)
			cfg.randomizeHeaderOrderSeed = &val
		}
	}

	browser := GetBrowserFromUserAgent(userAgent)
	spec := getSpecForBrowser(browser)

	if overrideTlsSpec != nil {
		cfg.tlsSpec = *overrideTlsSpec
	} else {
		val, err := spec.getTlsSpec(userAgent)
		if err != nil {
			return nil, err
		}

		cfg.tlsSpec = val
	}

	if overrideHeaderOrder != nil {
		cfg.headerOrder = overrideHeaderOrder
	} else {
		val, err := spec.getHeaderOrder(userAgent)
		if err != nil {
			return nil, err
		}

		cfg.headerOrder = &val
	}

	if overridePseudoHeaderOrder != nil {
		cfg.pseudoHeaderOrder = overridePseudoHeaderOrder
	} else {
		val, err := spec.getPseudoHeaderOrder(userAgent)
		if err != nil {
			return nil, err
		}

		cfg.pseudoHeaderOrder = &val
	}

	if overrideInitialSettings != nil {
		cfg.initialSettings = overrideInitialSettings
	} else {
		val, err := spec.getInitialSettings(userAgent)
		if err != nil {
			return nil, err
		}

		if opts.FindBoolOption(OptionDisableServerPush, false) {
			if enablePushIdx := slices.IndexFunc(val, func(x http2.Setting) bool {
				return x.ID == http2.SettingEnablePush
			}); enablePushIdx == -1 {
				val = append(val, http2.Setting{ID: http2.SettingEnablePush, Val: 0})
			} else if val[enablePushIdx].Val != 0 {
				return nil, fmt.Errorf("disable server push requested when specifically enabled")
			}
		}

		cfg.initialSettings = &val
	}

	if overrideDefaultConnFlow != nil {
		cfg.defaultConnFlow = overrideDefaultConnFlow
	} else {
		val, err := spec.getDefaultConnFlow(userAgent)
		if err != nil {
			return nil, err
		}

		cfg.defaultConnFlow = &val
	}

	if overridePriorityFrames != nil {
		cfg.priorityFrames = overridePriorityFrames
	} else {
		val, err := spec.getPriorityFrames(userAgent)
		if err != nil {
			return nil, err
		}

		cfg.priorityFrames = &val
	}

	if overrideInitialSettingsToSend != nil {
		cfg.initialSettingsToSend = overrideInitialSettingsToSend
	} else {
		val, err := spec.getInitialSettingsToSend(userAgent)
		if err != nil {
			return nil, err
		}

		if opts.FindBoolOption(OptionDisableServerPush, false) && !slices.Contains(val, http2.SettingEnablePush) {
			val = append(val, http2.SettingEnablePush)
		}

		cfg.initialSettingsToSend = &val
	}

	if cfg.randomizeHeaderOrderSeed != nil && cfg.headerOrder != nil {
		randomizedHeaders := make([]string, len(*cfg.headerOrder))
		copy(randomizedHeaders, *cfg.headerOrder)

		r := rand.New(rand.NewSource(*cfg.randomizeHeaderOrderSeed))
		r.Shuffle(len(randomizedHeaders), reflect.Swapper(randomizedHeaders))
		cfg.headerOrder = &randomizedHeaders
	}

	return &cfg, nil
}
