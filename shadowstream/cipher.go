package shadowstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
	"github.com/dgryski/go-camellia"
	"github.com/dgryski/go-idea"
	"github.com/dgryski/go-rc2"
	"github.com/geeksbaek/seed"
	"github.com/kierdavis/cfb8"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/salsa20/salsa"
)

// Cipher generates a pair of stream ciphers for encryption and decryption.
type Cipher interface {
	IVSize() int
	Encrypter(iv []byte) cipher.Stream
	Decrypter(iv []byte) cipher.Stream
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

// CTR mode
type ctrStream struct{ cipher.Block }

func (b *ctrStream) IVSize() int                       { return b.BlockSize() }
func (b *ctrStream) Decrypter(iv []byte) cipher.Stream { return b.Encrypter(iv) }
func (b *ctrStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCTR(b, iv) }

func AESCTR(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrStream{blk}, nil
}

// CFB mode
type cfbStream struct{ cipher.Block }

func (b *cfbStream) IVSize() int                       { return b.BlockSize() }
func (b *cfbStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewCFBDecrypter(b, iv) }
func (b *cfbStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCFBEncrypter(b, iv) }

func AESCFB(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// CFB8 mode
type cfb8Stream struct { cipher.Block }

func (b *cfb8Stream) IVSize() int                       { return b.BlockSize() }
func (b *cfb8Stream) Decrypter(iv []byte) cipher.Stream { return cfb8.NewDecrypter(b, iv) }
func (b *cfb8Stream) Encrypter(iv []byte) cipher.Stream { return cfb8.NewEncrypter(b, iv) }

func AESCFB8(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfb8Stream{blk}, nil
}

// OFB mode
type ofbStream struct{ cipher.Block }

func (b *ofbStream) IVSize() int                       { return b.BlockSize() }
func (b *ofbStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewOFB(b, iv) }
func (b *ofbStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewOFB(b, iv) }

func AESOFB(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ofbStream{blk}, nil
}

// bf-cfb
func BFCFB(key []byte) (Cipher, error) {
	blk, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// cast5-cfb
func CAST5CFB(key []byte) (Cipher, error) {
	blk, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// des-cfb
func DESCFB(key []byte) (Cipher, error) {
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// idea-cfb
func IDEACFB(key []byte) (Cipher, error) {
	blk, err := idea.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// rc2-cfb
func RC2CFB(key []byte) (Cipher, error) {
	blk, err := rc2.New(key, 16)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// seed-cfb
func SEEDCFB(key []byte) (Cipher, error) {
	blk, err := seed.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// camellia
func CamelliaCFB(key []byte) (Cipher, error) {
	blk, err := camellia.New(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

func CamelliaCFB8(key []byte) (Cipher, error) {
	blk, err := camellia.New(key)
	if err != nil {
		return nil, err
	}
	return &cfb8Stream{blk}, nil
}

// rc4
type rc4key []byte

func (k rc4key) IVSize() int                       { return 16 }
func (k rc4key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k rc4key) Encrypter(iv []byte) cipher.Stream {
	c, _ := rc4.NewCipher(k)
	return c
}

func RC4(key []byte) (Cipher, error) {
	return rc4key(key), nil
}

// rc4-md5
type rc4Md5key []byte

func (k rc4Md5key) IVSize() int {
	return 16
}

func (k rc4Md5key) Encrypter(iv []byte) cipher.Stream {
	h := md5.New()
	h.Write([]byte(k))
	h.Write(iv)
	rc4key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4key)
	return c
}

func (k rc4Md5key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func RC4MD5(key []byte) (Cipher, error) {
	return rc4Md5key(key), nil
}

// salsa20
type salsa20Stream struct{ key *[32]byte }

func (s salsa20Stream) IVSize() int                       { return 8 }
func (s salsa20Stream) Decrypter(iv []byte) cipher.Stream { return s.Encrypter(iv) }
func (s salsa20Stream) Encrypter(iv []byte) cipher.Stream {
	return &salsa20Cipher{
		nonce: iv,
		key:   *s.key,
	}
}

type salsa20Cipher struct {
	nonce   []byte
	key     [32]byte
	counter uint64
}

func (s *salsa20Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(fmt.Errorf("dst is smaller than src"))
	}
	padLen := int(s.counter % 64)
	buf := make([]byte, len(src)+padLen)

	var subNonce [16]byte
	copy(subNonce[:], s.nonce)
	binary.LittleEndian.PutUint64(subNonce[8:], uint64(s.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src)
	salsa.XORKeyStream(buf, buf, &subNonce, &s.key)
	copy(dst, buf[padLen:])

	s.counter += uint64(len(src))
}

func Salsa20(key []byte) (Cipher, error) {
	var fixedSizedKey [32]byte
	if len(key) != 32 {
		return nil, KeySizeError(32)
	}

	copy(fixedSizedKey[:], key)
	ciph := salsa20Stream{
		key: &fixedSizedKey,
	}

	return &ciph, nil
}

// chacha20
type chacha20key []byte

func (k chacha20key) IVSize() int                       { return 8 }
func (k chacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20key) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Chacha20(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return chacha20key(key), nil
}

// IETF-variant of chacha20
type chacha20ietfkey []byte

func (k chacha20ietfkey) IVSize() int                       { return chacha.INonceSize }
func (k chacha20ietfkey) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20ietfkey) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Chacha20IETF(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return chacha20ietfkey(key), nil
}

// xchacha20
type xchacha20key []byte

func (k xchacha20key) IVSize() int                       { return chacha.XNonceSize }
func (k xchacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k xchacha20key) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Xchacha20(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return xchacha20key(key), nil
}
