package token

import (
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

/*
Parse:	Verifica assinatura e algoritmo
			- Ler um token JWT bruto (string ou []byte).
			- Decodificar o header + claims.
			- Verificar a assinatura (se WithVerify(true) estiver ativo).
Valid:	Verifica expiração
			- exp (expiração)
			- nbf (not before)
			- iat (issued at)
*/

const prefeituraClaimKey = "cpa_prefeitura_id"
const typeClaimKey = "cpa_token_type"

type Token struct {
	RawToken     string
	PrefeituraID string
	TokenType    string
	Subject      string // sub
	Issuer       string // iss
	Expiration   string // exp
}

// Função exportada (primeira letra maiúscula)
func ParseToken(rawToken string) (Token, error) {
	if rawToken == "" {
		return Token{}, errors.New("no token informed")
	}
	verify := false
	parsedToken, err := jwt.Parse(
		[]byte(rawToken),
		jwt.WithVerify(verify),
		jwt.WithRequiredClaim(prefeituraClaimKey),
		jwt.WithRequiredClaim(typeClaimKey),
	)
	if err != nil {
		return Token{}, err
	}

	err = jwt.Validate(parsedToken, jwt.WithClock(jwt.ClockFunc(func() time.Time {
		return time.Now()
	})))
	if err != nil {
		return Token{}, err
	}

	prefeituraID, _ := parsedToken.Get(prefeituraClaimKey)
	prefeituraIDString, _ := prefeituraID.(string)

	tokenType, _ := parsedToken.Get(typeClaimKey)
	tokenTypeString, _ := tokenType.(string)

	ret := Token{
		RawToken:     rawToken,
		PrefeituraID: prefeituraIDString,
		TokenType:    tokenTypeString,
		Subject:      parsedToken.Subject(),
		Issuer:       parsedToken.Issuer(),
		Expiration:   parsedToken.Expiration().String(),
	}

	return ret, nil
}

/*
// Método exportado (primeira letra maiúscula)
func (t *Token) ValidateToken() err {
	err := token.Validate(jwt.WithClock(jwt.ClockFn(time.Now)))
	return err
}
*/
