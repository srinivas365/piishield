package piishield

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	os.Setenv("REDACT_PII", "true")

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

	expected := &Person{
		UserID:       "<email>",
		Fullname:     "<name>",
		Gender:       "<gender>",
		MobileNumber: "<mobile_number>",
		CreditCard:   "<credit_card>",
		Passport:     "<passport>",
		NationalID:   "<nation_id>",
		BankAccount:  "<bank_account>",
		Address:      "123 Main St",
		DOB:          "1990-01-01",
		SSN:          "123-45-6789",
		License:      "D1234567",
		Pincode:      1234,
	}

	actual := Redact(person)
	assert.ObjectsAreEqual(expected, actual)
}
