package main

import (
	"fmt"
	"log"

	"github.com/srinivas365/piiencrypt" // Replace with your actual module path
)

type Person struct {
	UserID       string `pii:"email" json:"user_id"`               // Email address
	Fullname     string `pii:"name" json:"fullname"`               // Full name
	Gender       string `pii:"gender" json:"gender"`               // Gender
	MobileNumber string `pii:"mobile_number" json:"mobile_number"` // Mobile number
	CreditCard   string `pii:"credit_card" json:"creditcard"`      // Credit card number
	Passport     string `pii:"passport" json:"passport"`           // Passport number
	NationalID   string `pii:"national_id" json:"national_id"`     // National ID
	BankAccount  string `pii:"bank_account" json:"bank_account"`   // Bank account number
	Address      string `json:"address"`                           // Address
	DOB          string `json:"dob"`                               // Date of birth
	SSN          string `json:"ssn"`                               // Social security number
	License      string `json:"license"`                           // Driver's license number
	Pincode      int    `json:"pincode"`                           // Not PII but included for completeness
}

func main() {
	// Create a PIIHook and handle any errors
	_, err := piiencrypt.NewPIIHook()
	if err != nil {
		log.Fatal("Error creating PIIHook", err)
	}

	person := &Person{
		UserID:       "user@example.com",
		Fullname:     "John Doe",
		Gender:       "Male",
		MobileNumber: "1234567890",
		CreditCard:   "1234-5678-9876-5432",
		Passport:     "A12345678",
		NationalID:   "123456789",
		BankAccount:  "9876543210",
		Address:      "123 Main St",
		DOB:          "1990-01-01",
		SSN:          "123-45-6789",
		License:      "D1234567",
		Pincode:      1234,
	}

	// Replace PII fields with placeholder tags using default mappings
	err = piiencrypt.ReplacePIITags(person)
	if err != nil {
		log.Fatalf("Error replacing PII tags: %v", err)
	}

	fmt.Printf("After Replacing PII Tags (Default Mappings): %+v", person)

	// Optionally, use a custom mapping file
	err = piiencrypt.ReplacePIITags(person, "pii_tags.json")
	if err != nil {
		log.Fatalf("Error replacing PII tags with custom mappings: %v", err)
	}

	fmt.Printf("After Replacing PII Tags (Custom Mappings): %+v\n\n", person)

	fmt.Println(person)
}
