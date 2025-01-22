package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/WhiCu/jwt"
)

var (
	ErrInvalidToken = errors.New("invalid token format")
)

func Unmarshal(data []byte, v *jwt.JWT) error {
	err := NewDecoder(bytes.NewReader(data)).Decode(v)
	return err
}

func (d *Decoder) Decode(j *jwt.JWT) error {
	// Считываем данные из bytes.Reader
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(d.r); err != nil {
		return err
	}

	// Разбиваем токен на части
	parts := strings.Split(buf.String(), ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	// Декодируем Header
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return err
	}
	var header jwt.Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return err
	}
	j.Header = header

	// Декодируем Payload
	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payloadBytes, &j.Payload); err != nil {
		return err
	}

	// Декодируем Signature
	signatureBytes, err := decodeBase64URL(parts[2])
	if err != nil {
		return err
	}
	j.Signature = signature{SignatureHash: string(signatureBytes)}
	return nil
}

// Вспомогательная функция для декодирования Base64URL
func decodeBase64URL(data string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(data)
}

type signature struct {
	SignatureHash string `json:"hash"`
}

func (s signature) Hash(_, _ []byte) ([]byte, error) {
	return []byte(s.SignatureHash), nil
}
