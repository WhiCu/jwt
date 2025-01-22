package decoder

import (
	"reflect"

	"github.com/WhiCu/jwt"
)

func Equal(a, b jwt.JWT) bool {
	return a.Equal(&b)
}

func EqualString(j jwt.JWT, other string) bool {
	var o *jwt.JWT
	Unmarshal([]byte(other), o, reflect.New(reflect.TypeOf(j.Payload)).Interface())
	return j.Equal(o)
}
