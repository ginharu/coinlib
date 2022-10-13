package keystore

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"log"
	"os"

	"github.com/cyrildou/coinlib/crypto"
	"github.com/cyrildou/coinlib/crypto/secp256k1"
	"github.com/cyrildou/coinlib/params"
	"github.com/cyrildou/coinlib/utils"
	//"fmt"
	//"github.com/cyrildou/eth-2-0/base"
)

const (
	encryptKeySize          = 32
	walletFile              = "wallet.dat"
	changeAddressNum uint32 = 20
)

var (
	walletMagic = utils.HexToBytes("0901419396d7679bf46d7c0c28a7a8eb2d793bea3c9bea222e7eedc77dc7e174")

	ErrNoWalletFile    = errors.New("no wallet file")
	ErrKeyNotFind      = errors.New("key not find")
	ErrWrongPasspharse = errors.New("mac not match")
	ErrFileNotEmpty    = errors.New("wallet file not empty")
)

type (

	// EncryptKey represents a encrypt key.
	EncryptKey [encryptKeySize]byte
)

// KeyStore represents the key storage manager.
type KeyStore struct {
	file          *os.File
	keys          map[utils.Address][]byte
	salt, iv, mac []byte
}

// New returns a new keystore instance.
func New() *KeyStore {
	return &KeyStore{
		keys: make(map[utils.Address][]byte),
		salt: make([]byte, 32),
		iv:   make([]byte, 16),
		mac:  make([]byte, 32),
	}
}

// Open opens the wallet file and load wallet data.
func (ks *KeyStore) open() (err error) {
	f, err := utils.OpenFile(walletFile)
	if err != nil {
		panic(err)
	}
	ks.file = f
	return err
}

func (ks *KeyStore) write(b []byte) (n int, err error) { return ks.file.Write(b) }
func (ks *KeyStore) close() error                      { return ks.file.Close() }
func (ks *KeyStore) read(b []byte) (n int, err error)  { return ks.file.Read(b) }

func (ks *KeyStore) AddAddress(newNum uint32, auth string) error {
	if utils.FileExist(walletFile) {
		if err := ks.open(); err != nil {
			return err
		}
		defer ks.close()

		addAddr, _ := utils.OpenFile("newaddrs.txt")
		defer addAddr.Close()

		addWalet, _ := utils.OpenFile("newwallet.dat")
		defer addWalet.Close()

		var (
			magic = make([]byte, 32)
			buf   = make([]byte, 4)
		)
		log.Println("add addresses")
		ks.read(magic)
		ks.read(ks.salt)
		ks.read(ks.iv)
		ks.read(ks.mac)
		ks.read(buf)
		// get old length
		oldNum := binary.LittleEndian.Uint32(buf)
		// write new wallet.dat
		newBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(newBuf, newNum+oldNum)
		addWalet.Write(walletMagic)
		addWalet.Write(ks.salt)
		addWalet.Write(ks.iv)
		addWalet.Write(ks.mac)
		addWalet.Write(newBuf)
		log.Println(magic, ks.salt, ks.iv, ks.mac, buf)

		for i := uint32(0); i < oldNum; i++ {
			var (
				addr       = make([]byte, 20)
				encryptKey = make([]byte, 32)
			)
			ks.read(addr)
			ks.read(encryptKey)
			addWalet.Write(addr)
			addWalet.Write(encryptKey)
			ks.keys[utils.BytesToAddress(addr)] = encryptKey
		}
		for i := uint32(0); i < newNum; i++ {
			priv, pub := generateKey()
			addr := params.Params.AddressHashFunc(pub)
			derivedKey := crypto.GetDerivedKey(auth, ks.salt)
			encryptKey, err := crypto.Encrypt(derivedKey[:16], priv, ks.iv)
			if err != nil {
				return err
			}
			addWalet.Write(addr)
			addWalet.Write(encryptKey)

			//strTemp := params.Params.ToAddress([]byte(addr))
			//strHex := getHex(strTemp, auth)
			//addAddr.WriteString(fmt.Sprintf("%s %s", strTemp, strHex))
			//addAddr.WriteString("\n")
			//
			//ks.keys[utils.BytesToAddress(addr)] = encryptKey

			addAddr.WriteString(params.Params.ToAddress(addr))
			addAddr.WriteString("\n")
			ks.keys[utils.BytesToAddress(addr)] = encryptKey

		}
		return nil
	}
	return ErrNoWalletFile
}

//// 获取地址hex串
//func getHex(strAddress string, auth string) string {
//	origin := fmt.Sprintf("%s%s%s", auth, base.ColdAddrSalt, strAddress)
//	strSalt := base.SaltShuttle(origin)
//	return base.Md5string(strSalt)
//}

// GenerateKeys generate many pair of private/public key, and write it to file.
func (ks *KeyStore) GenerateKeys(num uint32, auth string) error {
	ks.open()
	if ks.file != nil {
		fileInfo, err := ks.file.Stat()
		if err != nil {
			return err
		} else if fileInfo.Size() > 0 {
			return ErrFileNotEmpty
		}
		// Write Address
		addrFile, _ := utils.OpenFile("addrs.txt")
		defer addrFile.Close()

		// Write Change Address
		changeFile, _ := utils.OpenFile("changes.txt")
		defer changeFile.Close()

		// Write EncryptInfo
		ks.salt, ks.iv = crypto.GenEncryptInfo()
		derivedKey := crypto.GetDerivedKey(auth, ks.salt)
		ks.mac = crypto.Keccak256(derivedKey[16:32])

		ks.write(walletMagic)
		ks.write(ks.salt)
		ks.write(ks.iv)
		ks.write(ks.mac)

		// write length
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, num+changeAddressNum)
		ks.write(buf)

		// Write Address->Key
		for i := uint32(0); i < num+changeAddressNum; i++ {
			priv, pub := generateKey()
			addr := params.Params.AddressHashFunc(pub)
			encryptKey, err := crypto.Encrypt(derivedKey[:16], priv, ks.iv)
			if err != nil {
				panic(err)
			}

			ks.write(addr)

			//strTemp := params.Params.ToAddress(addr)
			//strHex := getHex(strTemp, auth)

			if i < changeAddressNum { // 系统地址
				changeFile.WriteString(params.Params.ToAddress(addr))
				//changeFile.WriteString(fmt.Sprintf("%s %s", strTemp, strHex))
				changeFile.WriteString("\n")
			} else { // 用户地址
				addrFile.WriteString(params.Params.ToAddress(addr))
				//addrFile.WriteString(fmt.Sprintf("%s %s", strTemp, strHex))
				addrFile.WriteString("\n")
			}
			// addrFile.WriteString(fmt.Sprintf("0x%x%x\n", addr, priv))

			ks.write(encryptKey)
			ks.keys[utils.BytesToAddress(addr)] = encryptKey

		}
		ks.close()
		return nil
	}
	return ErrNoWalletFile
}

// Load loads wallet data.
func (ks *KeyStore) Load() error {
	if utils.FileExist(walletFile) {
		if err := ks.open(); err != nil {
			return err
		}

		// Read DecryptInfo
		var (
			magic = make([]byte, 32)
			buf   = make([]byte, 4)
		)
		log.Println("magic")
		log.Println(ks.read(magic))
		ks.read(ks.salt)
		ks.read(ks.iv)
		ks.read(ks.mac)

		ks.read(buf)
		num := binary.LittleEndian.Uint32(buf)
		log.Println(magic, ks.salt, ks.iv, ks.mac, buf)
		log.Printf("load keys %d addrs, %d change addrs", num, changeAddressNum)
		for i := uint32(0); i < num+changeAddressNum; i++ {
			var (
				addr       = make([]byte, 20)
				encryptKey = make([]byte, 32)
			)
			ks.read(addr)
			ks.read(encryptKey)

			ks.keys[utils.BytesToAddress(addr)] = encryptKey
		}
		return nil
	}
	return ErrNoWalletFile
}

// GetPrivkey gets privatekey by address.
func (ks KeyStore) GetPrivkey(addr utils.Address, auth string) (*ecdsa.PrivateKey, error) {
	// ks.mu.Lock()
	// defer ks.mu.UnLock()
	encryptKey, ok := ks.keys[addr]
	if !ok {
		return nil, ErrKeyNotFind
	}

	derivedKey := crypto.GetDerivedKey(auth, ks.salt)
	privBytes, err := crypto.Decrypt(derivedKey[:16], encryptKey, ks.iv, ks.mac)
	if err != nil {
		return nil, err
	}

	return (*ecdsa.PrivateKey)(secp256k1.ToECDSA(privBytes)), err
}

// AppendKeys appends keys to wallet file.
// TODO.
func (ks *KeyStore) AppendKeys(num int, auth string) error {
	return nil
}

func generateKey() (priv, pub []byte) {
	privKey, err := secp256k1.GenerateKey()
	if err != nil {
		panic(err)
	}

	return privKey.SecretBytes(), privKey.Public().Bytes()
}
