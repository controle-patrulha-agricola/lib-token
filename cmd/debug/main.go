package main

import (
	"fmt"
	"log"

	token "github.com/controle-patrulha-agricola/lib-token"
)

func main() {
	fmt.Println("main")
	// Token JWT de exemplo (obviamente falso!)
	rawToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

	prefID, err := token.ParseToken(rawToken)
	if err != nil {
		log.Fatalf("Token inválido: %v", err)
	}

	fmt.Println("Prefeitura ID extraído:", prefID)
}
