package decoder

import "github.com/WhiCu/jwt"

func Equal(a, b jwt.JWT) bool {
	return a.Equal(&b)
}

func EqualString(j jwt.JWT, other string) bool {
	var o *jwt.JWT
	Unmarshal([]byte(other), o)
	return j.Equal(o)
}
