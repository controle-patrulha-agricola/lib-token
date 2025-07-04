package token

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

func TestParseToken_ValidToken(t *testing.T) {
	// Cria token válido para teste
	tok, err := jwt.NewBuilder().
		Issuer("cpa").
		Subject("123").
		Claim(prefeituraClaimKey, "pref-123").
		Claim(typeClaimKey, "access").
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	assert.NoError(t, err)

	// Serializa o token como raw
	raw, err := jwt.NewSerializer().Serialize(tok)
	assert.NoError(t, err)

	// Chama sua função real
	parsed, err := ParseToken(string(raw))
	assert.NoError(t, err)
	assert.Equal(t, "pref-123", parsed.PrefeituraID)
	assert.Equal(t, "access", parsed.TokenType)
	assert.Equal(t, "123", parsed.Subject)
	assert.Equal(t, "cpa", parsed.Issuer)
	assert.NotEmpty(t, parsed.Expiration)
}

func TestParseToken_ExpiredToken(t *testing.T) {
	// Cria token já expirado
	tok, err := jwt.NewBuilder().
		Issuer("cpa").
		Subject("123").
		Claim(prefeituraClaimKey, "pref-123").
		Claim(typeClaimKey, "access").
		Expiration(time.Now().Add(-1 * time.Hour)). // Expirado!
		Build()
	assert.NoError(t, err)

	raw, err := jwt.NewSerializer().Serialize(tok)
	assert.NoError(t, err)

	// Executa ParseToken real
	_, err = ParseToken(string(raw))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exp") // Opcional: checa mensagem de expiração
}

func TestParseToken_MissingPrefeituraID(t *testing.T) {
	// Cria token válido mas sem prefeitura_id
	tok, err := jwt.NewBuilder().
		Issuer("cpa").
		Subject("123").
		Claim(typeClaimKey, "access"). // Só typeClaimKey, mas falta prefeituraClaimKey
		Expiration(time.Now().Add(1 * time.Hour)).
		Build()
	assert.NoError(t, err)

	raw, err := jwt.NewSerializer().Serialize(tok)
	assert.NoError(t, err)

	_, err = ParseToken(string(raw))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), prefeituraClaimKey)
}
