package params

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ginharu/coinlib/crypto"
	"github.com/ginharu/coinlib/encoding/base58"
)

// ChainParams defines the chain parameters.
type ChainParams struct {
	PubkeyAddressPrefix byte
	ScriptAddressPrefix byte
	PrivateKeyPrefix    byte

	// Segwit
	WitnessPubkeyPrefix     byte
	WitnessScriptAddrPrefix byte

	HDPrivateKeyPrefix [4]byte
	HDPublicKeyPrefix  [4]byte

	// DNSSeeds                []string
	// GenesisBlock            Block
	DefaultPort uint32
	RPCPort     uint32

	CoinbaseMaturity uint8
	Coin             *big.Int
	CoinType         string

	AddressHashFunc func([]byte) []byte
	ToAddress       func([]byte) string

	TxGas   *big.Int
	ChainID *big.Int
}

const (
	BTC       = "btc"
	LTC       = "ltc"
	BCC       = "bcc"
	ETH       = "eth"
	ETH1      = "eth1"
	ETC       = "etc"
	HAP       = "hap"
	HPB       = "hpb"
	ZXT       = "zxt"
	QKI       = "qki"
	PRIETHWTX = "priethwtx"
	MATIC     = "matic"
)

var (
	// Params represents the coin parameters you select.
	Params *ChainParams

	btcMainnetParams = &ChainParams{
		PubkeyAddressPrefix: 0,
		ScriptAddressPrefix: 5,
		PrivateKeyPrefix:    128,

		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 8333,
		RPCPort:     8332,

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{0}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.Encode(a)
		},

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),
		CoinType:         BTC,
	}

	ltcMainnetParams = &ChainParams{
		PubkeyAddressPrefix: 48,
		ScriptAddressPrefix: 5,
		PrivateKeyPrefix:    176,

		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 9333,
		RPCPort:     9332,

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),
		CoinType:         LTC,

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{48}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.Encode(a)
		},
	}

	bccMainnetParams = &ChainParams{
		PubkeyAddressPrefix:     0,
		ScriptAddressPrefix:     5,
		PrivateKeyPrefix:        128,
		WitnessPubkeyPrefix:     0,
		WitnessScriptAddrPrefix: 0,

		HDPrivateKeyPrefix: [4]byte{0x04, 0x88, 0xad, 0xe4},
		HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 8333,
		RPCPort:     8332,

		CoinbaseMaturity: 100,
		Coin:             big.NewInt(1e8),

		AddressHashFunc: crypto.Hash160,
		ToAddress: func(b []byte) string {
			a := append([]byte{0}, b[:]...)
			checkSum := crypto.DoubleSha256(a)
			a = append(a, checkSum[:4]...)
			return base58.Encode(a)
		},

		CoinType: BCC,
	}

	ethMainnetParams = &ChainParams{
		// PubkeyAddressPrefix:     0,
		// ScriptAddressPrefix:     0,
		// PrivateKeyPrefix:        0,
		// WitnessPubkeyPrefix:     0,
		// WitnessScriptAddrPrefix: 0,

		// HDPrivateKeyPrefix: [4]byte{0x00, 0x, 0xad, 0xe4},
		// HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         ETH,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(1),
	}
	etcMainnetParams = &ChainParams{
		// PubkeyAddressPrefix:     0,
		// ScriptAddressPrefix:     0,
		// PrivateKeyPrefix:        0,
		// WitnessPubkeyPrefix:     0,
		// WitnessScriptAddrPrefix: 0,

		// HDPrivateKeyPrefix: [4]byte{0x00, 0x, 0xad, 0xe4},
		// HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         ETC,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(61),
	}
	hapMainnetParams = &ChainParams{
		// PubkeyAddressPrefix:     0,
		// ScriptAddressPrefix:     0,
		// PrivateKeyPrefix:        0,
		// WitnessPubkeyPrefix:     0,
		// WitnessScriptAddrPrefix: 0,

		// HDPrivateKeyPrefix: [4]byte{0x00, 0x, 0xad, 0xe4},
		// HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         HAP,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(1),
	}
	hpbMainnetParams = &ChainParams{
		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         HPB,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(269),
	}
	zxtMainnetParams = &ChainParams{
		// PubkeyAddressPrefix:     0,
		// ScriptAddressPrefix:     0,
		// PrivateKeyPrefix:        0,
		// WitnessPubkeyPrefix:     0,
		// WitnessScriptAddrPrefix: 0,

		// HDPrivateKeyPrefix: [4]byte{0x00, 0x, 0xad, 0xe4},
		// HDPublicKeyPrefix:  [4]byte{0x04, 0x88, 0xb2, 0x1e},

		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         ZXT,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(1),
	}

	qkiMainnetParams = &ChainParams{
		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         QKI,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(269),
	}
	eth1MainnetParams = &ChainParams{
		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         ETH1,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(269),
	}

	priethwtxMainnetParams = &ChainParams{
		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         PRIETHWTX,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(198408),
	}

	maticMainnetParams = &ChainParams{
		DefaultPort: 30303,
		RPCPort:     8545,

		CoinbaseMaturity: 0,
		Coin:             big.NewInt(1e18),
		CoinType:         MATIC,

		AddressHashFunc: func(b []byte) []byte { return crypto.Keccak256(b[1:])[12:] },
		ToAddress:       func(b []byte) string { return fmt.Sprintf("0x%x", b) },

		TxGas:   big.NewInt(21000),
		ChainID: big.NewInt(137),
	}
)

// SelectChain selects the chain parameters to use
// coinType is one of 'bitcoin', 'litecoin'
// name is one of 'mainnet', 'testnet', or 'regtest'
// Default chain is 'mainnet'
func SelectChain(ct string) *ChainParams {
	switch strings.ToLower(ct) {
	case BTC:
		Params = btcMainnetParams
	case LTC:
		Params = ltcMainnetParams
	case BCC:
		Params = bccMainnetParams
	case ETH:
		Params = ethMainnetParams
	case ETC:
		Params = etcMainnetParams
	case HAP:
		Params = hapMainnetParams
	case HPB:
		Params = hpbMainnetParams
	case ZXT:
		Params = zxtMainnetParams
	case QKI:
		Params = qkiMainnetParams
	case ETH1:
		Params = eth1MainnetParams
	case PRIETHWTX:
		Params = priethwtxMainnetParams
	case MATIC:
		Params = maticMainnetParams
	}

	return Params
}
