package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/WhiCu/jwt"
	"github.com/mitchellh/mapstructure"
)

var (
	// ErrInvalidToken описывает ошибку некорректного формата токена.
	ErrInvalidToken = errors.New("invalid token format")

	// ErrInvalidJwtPointer возникает при передаче неверного указателя на jwt.JWT.
	ErrInvalidJwtPointer = errors.New("invalid jwt pointer")

	// ErrInvalidPayloadStruct возникает, если структура payload не является указателем.
	ErrInvalidPayloadStruct = errors.New("payloadStruct must be a pointer to a struct or nil")

	// ErrDecodingHeader возникает при ошибке декодирования заголовка.
	ErrDecodingHeader = errors.New("error decoding JWT header")

	// ErrDecodingPayload возникает при ошибке декодирования полезной нагрузки.
	ErrDecodingPayload = errors.New("error decoding JWT payload")

	// ErrDecodingSignature возникает при ошибке декодирования подписи.
	ErrDecodingSignature = errors.New("error decoding JWT signature")
)

// Unmarshal — десериализует данные в структуру JWT.
func Unmarshal(data []byte, v *jwt.JWT, payloadStruct any) error {
	err := NewDecoder(bytes.NewReader(data)).Decode(v, payloadStruct)
	return err
}

// Decode — декодирует JWT токен в объект jwt.JWT.
func (d *Decoder) Decode(j *jwt.JWT, payloadStruct any) error {
	if j == nil {
		return ErrInvalidJwtPointer
	}

	// Считываем данные
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(d.r); err != nil {
		return err
	}

	// Разбиваем токен
	parts := strings.Split(buf.String(), ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	// Декодируем Header
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return ErrDecodingHeader
	}
	var header jwt.Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return ErrDecodingHeader
	}
	j.Header = header

	// Декодируем Payload
	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return ErrDecodingPayload
	}
	if err := json.Unmarshal(payloadBytes, &j.Payload); err != nil {
		return ErrDecodingPayload
	}

	// Декодируем в структуру, если она передана
	if payloadStruct != nil {
		if reflect.ValueOf(payloadStruct).Kind() != reflect.Pointer {
			return ErrInvalidPayloadStruct
		}
		mapstructure.Decode(j.Payload, payloadStruct)
		j.Payload = reflect.ValueOf(payloadStruct).Elem().Interface()
	}

	// Декодируем Signature
	signatureBytes, err := decodeBase64URL(parts[2])
	if err != nil {
		return ErrDecodingSignature
	}
	j.Signature = signature{SignatureHash: string(signatureBytes)}

	return nil
}

// decodeBase64URL — декодирует строку в формате Base64URL.
func decodeBase64URL(data string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(data)
}

// signature — структура для подписи JWT.
type signature struct {
	SignatureHash string `json:"hash"`
}

// Hash — возвращает хэш подписи.
func (s signature) Hash(_, _ []byte) ([]byte, error) {
	return []byte(s.SignatureHash), nil
}

// // Преобразование карты в динамическую структуру (Зачем я вообще это сделал?)
// func mapToStruct(payloadMap map[string]interface{}) (any, error) {
// 	var fields []reflect.StructField
// 	title := cases.Title(language.Und)

// 	// Создание полей структуры
// 	keyToField := make(map[string]string, len(payloadMap))
// 	for key, value := range payloadMap {
// 		exportedName := title.String(key)
// 		keyToField[key] = exportedName
// 		fields = append(fields, reflect.StructField{
// 			Name: exportedName,
// 			Type: reflect.TypeOf(value),
// 			Tag:  reflect.StructTag(`json:"` + key + `"`),
// 		})
// 	}

// 	// Создание структуры
// 	structType := reflect.StructOf(fields)
// 	instance := reflect.New(structType).Elem()

// 	// Заполнение полей структуры
// 	for key, value := range payloadMap {
// 		fieldName := keyToField[key]
// 		instance.FieldByName(fieldName).Set(reflect.ValueOf(value))
// 	}

// 	return instance.Interface(), nil
// }
