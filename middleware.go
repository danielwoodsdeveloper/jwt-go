package jwt

import (
	"net/http"
	"strings"
)

// Middleware validator for checking the authority of HTTP requests.
// Accepts any net/http handler func and the global secret against which
// the JWT token was created, validating the token and passing through to
// the handler func. Will return an appropriate HTTP status response if
// an invalid token is sent
func ValidateAccess(next http.HandlerFunc, secret string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("authorization")
		if auth != "" {
			bearerToken := strings.Split(auth, " ")
			if len(bearerToken) == 2 {
				token, err := Parse(bearerToken[1], func(token *Token) (interface{}, error) {
					_, ok := token.Method.(*SigningMethodHMAC)
					if !ok {
						return nil, nil
					}

					return []byte(secret), nil
				})

				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if token.Valid {
					next(w, r)
					return
				}
			}
		}

		w.WriteHeader(http.StatusBadRequest)
		return
	})
}