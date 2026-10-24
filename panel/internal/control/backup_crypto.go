package control

// Recovery files contain peer tokens and private keys. The authenticated envelope
// is intentionally independent of panel credentials and installation identity.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

const BackupMaxBytes = 28 * 1024 * 1024
const backupPlainLimit = 20 * 1024 * 1024
const backupFormat = "gtm-recovery"
const backupKDF = "pbkdf2-sha256-600000"

type backupEnvelope struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Payload []byte `json:"payload"`
}

func backupDecode(text string, value any) error {
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if e := d.Decode(value); e != nil {
		return errors.New("invalid recovery document")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one recovery document required")
	}
	return nil
}
func backupCipher(password string, salt []byte) (cipher.AEAD, error) {
	if utf8.RuneCountInString(password) < 8 || len(password) > 256 || !utf8.ValidString(password) {
		return nil, errors.New("backup password needs at least 8 characters and at most 256 UTF-8 bytes")
	}
	key := pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func sealBackup(value any, password string) (string, error) {
	plain, e := json.Marshal(value)
	if e != nil {
		return "", e
	}
	defer clear(plain)
	if len(plain) > backupPlainLimit {
		return "", errors.New("recovery data exceeds 20 MiB")
	}
	env := backupEnvelope{Format: backupFormat, Version: 1, KDF: backupKDF, Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	if _, e = rand.Read(env.Salt); e != nil {
		return "", e
	}
	if _, e = rand.Read(env.Nonce); e != nil {
		return "", e
	}
	aead, e := backupCipher(password, env.Salt)
	if e != nil {
		return "", e
	}
	env.Payload = aead.Seal(nil, env.Nonce, plain, []byte(backupFormat+":1:"+backupKDF))
	data, e := json.Marshal(env)
	return string(data), e
}
func openBackup(text, password string, value any) error {
	if len(text) > BackupMaxBytes {
		return errors.New("recovery file exceeds 28 MiB")
	}
	var env backupEnvelope
	if e := backupDecode(text, &env); e != nil {
		return e
	}
	if env.Format != backupFormat || env.Version != 1 || env.KDF != backupKDF || len(env.Salt) != 16 || len(env.Nonce) != 12 || len(env.Payload) < 16 || len(env.Payload) > backupPlainLimit+16 {
		return errors.New("unsupported or invalid recovery format")
	}
	aead, e := backupCipher(password, env.Salt)
	if e != nil {
		return e
	}
	plain, e := aead.Open(nil, env.Nonce, env.Payload, []byte(backupFormat+":1:"+backupKDF))
	if e != nil {
		return errors.New("incorrect backup password or damaged recovery file")
	}
	defer clear(plain)
	return backupDecode(string(plain), value)
}
