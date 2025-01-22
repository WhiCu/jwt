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

// Ошибки
var (
	errNotAStruct = errors.New("payload must be a struct")
)

// JWT структура
type JWT struct {
	Header    Header
	Payload   any
	Signature Signature
}

// Конструктор для JWT
func New(h Header, p any, s Signature) (*JWT, error) {
	if !isStruct(p) {
		return nil, errNotAStruct
	}
	return &JWT{
		Header:    h,
		Payload:   p,
		Signature: s,
	}, nil
}

// Вспомогательная функция для проверки структуры
func isStruct(v any) bool {
	if v == nil {
		return false
	}
	return reflect.ValueOf(v).Kind() == reflect.Struct
}

// Метод для генерации JWT-токена
func (j *JWT) Generate() (string, error) {
	// Сериализация заголовка
	headerBytes, err := j.Header.Bytes()
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	// Сериализация payload
	payloadBytes, err := json.Marshal(j.Payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	// Задание кодера
	base64Encoder := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Базовая кодировка токена
	headerEncoded := base64Encoder.EncodeToString(headerBytes)
	payloadEncoded := base64Encoder.EncodeToString(payloadBytes)

	// Создание подписи
	signature, err := j.Signature.Hash([]byte(headerEncoded), []byte(payloadEncoded))
	if err != nil {
		return "", fmt.Errorf("failed to generate signature: %w", err)
	}
	signatureEncoded := base64Encoder.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded), nil
}

func (j *JWT) Equal(other *JWT) bool {
	if j.Header.Alg != other.Header.Alg {
		return false
	}
	if j.Header.Typ != other.Header.Typ {
		return false
	}
	if !reflect.DeepEqual(j.Payload, other.Payload) {
		return false
	}
	return true
}

// Структура Header
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Конструктор Header
func NewHeader(alg, typ string) Header {
	return Header{
		Alg: alg,
		Typ: typ,
	}
}

// Метод для преобразования Header в JSON
func (h Header) Bytes() ([]byte, error) {
	return json.Marshal(h)
}

// Интерфейс Signature
type Signature interface {
	Hash(header, payload []byte) ([]byte, error)
}

// HS256 реализация Signature
type HS256Signature struct {
	Secret string
}

// Метод Hash для HS256
func (s HS256Signature) Hash(header, payload []byte) ([]byte, error) {
	// Конкатенация данных
	data := fmt.Sprintf("%s.%s", header, payload)
	// Генерация подписи
	h := hmac.New(sha256.New, []byte(s.Secret))
	h.Write([]byte(data))
	return h.Sum(nil), nil
}
