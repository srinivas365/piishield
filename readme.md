# piishield

**piishield** is a Go package for protecting sensitive information by redacting personally identifiable information (PII). It supports redacting data in structs, nested structs, maps, and slices, making it versatile for various use cases in data privacy and security.

## Features

- **Redacts PII in Structs**: Replace sensitive fields with placeholder values.
- **Supports Nested Structs**: Handles PII redaction in nested structs.
- **Redacts Maps**: Redacts PII fields in map data structures.
- **Handles Slices**: Redacts PII fields in slices of structs.

## Installation

To install `piishield`, use the following Go command:

```bash
go get github.com/srinivas365/piishield
```

## Usage

### Importing the Package

```go
import "github.com/srinivas365/piishield"
```

### Example

Here’s an example of how to use `piishield` to redact PII data:

```go
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
```

### Redacting Based on Environment Variable

The `piishield.Redact` function can be enabled or disabled based on the `REDACT_PII` environment variable. 

- **Enable Redaction**: Set the environment variable `REDACT_PII` to `"true"`:

  ```bash
  export REDACT_PII=true
  ```

- **Disable Redaction**: Unset the environment variable or set it to any value other than `"true"`:

  ```bash
  unset REDACT_PII
  ```

When the `REDACT_PII` environment variable is set to `"true"`, the `piishield.Redact` function will replace PII fields with placeholder values as defined in the `DefaultPIIMappings`. If the environment variable is not set to `"true"`, the function will return the original data without any modifications.


### Redact Function

The `Redact` function takes an interface and returns a map with PII fields replaced with placeholders based on default mappings. It supports:

- **Structs**: Directly redacts fields in the struct.
- **Nested Structs**: Handles redaction in nested struct fields.
- **Maps**: Redacts PII fields in map structures.
- **Slices**: Redacts PII fields in slices of structs.

### Function Signature

```go
func Redact(v interface{}) map[string]interface{}
```

## Default Mappings

By default, `piishield` uses the following mappings for PII redaction:

```json
{
	"email":                  "<email>",
	"name":                   "<name>",
	"gender":                 "<gender>",
	"mobile_number":          "<mobile_number>",
	"credit_card":            "<credit_card>",
	"passport":               "<passport>",
	"national_id":            "<nation_id>",
	"bank_account":           "<bank_account>",
	"address":                "<address>",
	"dob":                    "<dob>",
	"ssn":                    "<ssn>",
	"license":                "<license>",
	"username":               "<username>",
	"password":               "<password>",
	"pin":                    "<pin>",
	"employee_id":            "<employee_id>",
	"vehicle_registration":   "<vehicle_registration>",
	"insurance_policy":       "<insurance_policy>",
	"medical_record":         "<medical_record>",
	"bank_routing_number":    "<bank_routing_number>",
	"tax_id":                 "<tax_id>",
	"crypto_wallet":          "<crypto_wallet>",
	"biometric_data":         "<biometric_data>",
	"home_phone":             "<home_phone>",
	"work_phone":             "<work_phone>",
	"fax_number":             "<fax_number>",
	"social_media_handle":    "<social_media_handle>",
	"marital_status":         "<marital_status>",
	"education_level":        "<education_level>",
	"employment_history":     "<employment_history>",
	"salary":                 "<salary>",
	"income_tax_return":      "<income_tax_return>",
	"credit_score":           "<credit_score>",
	"membership_id":          "<membership_id>",
	"loyalty_card_number":    "<loyalty_card_number>",
	"subscription_id":        "<subscription_id>",
	"event_attendance":       "<event_attendance>",
	"purchase_history":       "<purchase_history>",
	"location_data":          "<location_data>",
	"wifi_networks":          "<wifi_networks>",
	"device_id":              "<device_id>",
	"authentication_token":   "<authentication_token>",
	"session_id":             "<session_id>",
	"device_serial_number":   "<device_serial_number>",
	"account_number":         "<account_number>",
	"routing_number":         "<routing_number>",
	"credit_card_expiration": "<credit_card_expiration>",
	"driver_license_number":  "<driver_license_number>",
	"bank_statement":         "<bank_statement>",
	"utility_bills":          "<utility_bills>",
	"personal_references":    "<personal_references>",
	"voter_id":               "<voter_id>",
	"healthcare_id":          "<healthcare_id>",
	"patient_id":             "<patient_id>",
	"biometric_fingerprint":  "<biometric_fingerprint>",
	"biometric_face_data":    "<biometric_face_data>",
	"digital_signature":      "<digital_signature>",
	"security_question":      "<security_question>",
	"security_answer":        "<security_answer>",
	"medical_history":        "<medical_history>",
	"emergency_contact":      "<emergency_contact>"
}
```

You can customize the default mappings for PII tags by modifying the `DefaultPIIMappings` variable in the `piishield` package. If needed, you can also extend the `Redact` function to accept custom mappings or configurations.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Feel free to adjust the content based on additional features or specific instructions relevant to your package.