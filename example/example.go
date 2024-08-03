package main

import (
	"fmt"

	pii "github.com/srinivas365/piishield"
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

type Patient struct {
	PersonDetails Person
	PatientID     string `pii:"patient_id" json:"patient_id"`
}

func main() {
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

	patient := &Patient{
		PersonDetails: *person,
		PatientID:     "19324924",
	}

	var persons []Person
	persons = append(persons, *person)

	var patients []Patient
	patients = append(patients, *patient)

	var patientMap = make(map[string]Patient)
	patientMap = map[string]Patient{
		"srinivas365": *patient,
	}

	fmt.Printf("Before: %+v\n\n", person)
	fmt.Printf("After Replacing PII Tags (Default Mappings): %+v\n\n", pii.Redact(person))
	fmt.Printf("After: %+v\n\n", person)

	fmt.Printf("Before: %+v\n\n", patient)
	fmt.Printf("After Replacing PII Tags (Default Mappings): %+v\n\n", pii.Redact(patient))
	fmt.Printf("After: %+v\n\n", patient)

	fmt.Printf("Before: %+v\n\n", persons)
	fmt.Printf("After Replacing PII Tags (Default Mappings): %+v\n\n", pii.Redact(persons))
	fmt.Printf("After: %+v\n\n", persons)

	fmt.Printf("Before: %+v\n\n", patients)
	fmt.Printf("After Replacing PII Tags (Default Mappings): %+v\n\n", pii.Redact(patients))
	fmt.Printf("After: %+v\n\n", patients)

	fmt.Printf("Before: %+v\n\n", patientMap)
	fmt.Printf("After Replacing PII Tags (Default Mappings): %+v\n\n", pii.Redact(patientMap))
	fmt.Printf("After: %+v\n\n", patientMap)

}
