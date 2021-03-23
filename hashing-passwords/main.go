package main

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {

	pass := "password123😀"

	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	// log.Println(base64.StdEncoding.EncodeToString([]byte(hashedPass)))

	err = comparePasswords(pass, hashedPass)
	if err != nil {
		log.Fatalln("Not logged in")
	}

	log.Println("Logged In")

	// fmt.Println(base64.StdEncoding.EncodeToString([]byte("user:pass")))
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return nil, fmt.Errorf("Error in generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

func comparePasswords(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password %w", err)
	}
	return nil

}
