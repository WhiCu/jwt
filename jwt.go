package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// Общие ошибки
var (
	ErrNotAStruct      = errors.New("payload must be a struct")
	ErrFailedHeader    = errors.New("failed to encode header")
	ErrFailedPayload   = errors.New("failed to encode payload")
	ErrFailedSignature = errors.New("failed to generate signature")
)

// JWT представляет структуру JSON Web Token.
type JWT struct {
	Header    Header
	Payload   any
	Signature Signature
}

// New создаёт новый объект JWT.
// Проверяет, чтобы payload был структурой.
func New(h Header, p any, s Signature) (*JWT, error) {
	if !isStruct(p) {
		return nil, ErrNotAStruct
	}
	return &JWT{
		Header:    h,
		Payload:   p,
		Signature: s,
	}, nil
}

// isStruct проверяет, является ли значение структурой.
func isStruct(v any) bool {
	if v == nil {
		return false
	}
	return reflect.ValueOf(v).Kind() == reflect.Struct
}

// Generate создаёт подписанный JWT-токен в формате `header.payload.signature`.
func (j *JWT) Generate() (string, error) {
	// Сериализация заголовка
	headerBytes, err := j.Header.Bytes()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFailedHeader, err)
	}

	// Сериализация payload
	payloadBytes, err := json.Marshal(j.Payload)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFailedPayload, err)
	}

	// Кодирование в Base64URL без паддинга
	base64Encoder := base64.URLEncoding.WithPadding(base64.NoPadding)
	headerEncoded := base64Encoder.EncodeToString(headerBytes)
	payloadEncoded := base64Encoder.EncodeToString(payloadBytes)

	// Создание подписи
	signature, err := j.Signature.Hash([]byte(headerEncoded), []byte(payloadEncoded))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFailedSignature, err)
	}
	signatureEncoded := base64Encoder.EncodeToString(signature)

	// Формирование JWT-токена
	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded), nil
}

// Equal сравнивает два JWT-токена на равенство (без учёта подписи).
func (j *JWT) Equal(other *JWT) bool {
	if j.Header.Alg != other.Header.Alg || j.Header.Typ != other.Header.Typ {
		return false
	}
	return reflect.DeepEqual(j.Payload, other.Payload)
}

// Header представляет заголовок JWT.
type Header struct {
	Alg string `json:"alg"` // Алгоритм подписи
	Typ string `json:"typ"` // Тип токена
}

// NewHeader создаёт новый Header с заданным алгоритмом и типом.
func NewHeader(alg, typ string) Header {
	return Header{
		Alg: alg,
		Typ: typ,
	}
}

// Bytes сериализует заголовок в JSON.
func (h Header) Bytes() ([]byte, error) {
	return json.Marshal(h)
}

// Signature интерфейс, представляющий алгоритм подписи JWT.
type Signature interface {
	Hash(header, payload []byte) ([]byte, error)
}

// HS256Signature реализует алгоритм подписи HMAC-SHA256.
type HS256Signature struct {
	Secret string // Секретный ключ для подписи
}

// Hash вычисляет HMAC-SHA256 для заголовка и payload.
func (s HS256Signature) Hash(header, payload []byte) ([]byte, error) {
	// Формирование строки данных для подписи
	data := fmt.Sprintf("%s.%s", header, payload)
	// Вычисление HMAC-SHA256
	h := hmac.New(sha256.New, []byte(s.Secret))
	h.Write([]byte(data))
	return h.Sum(nil), nil
}
