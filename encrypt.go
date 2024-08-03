package piiencrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/rs/zerolog"
)

// DefaultPIIMappings provides default mappings for PII tags.
var DefaultPIIMappings = map[string]string{
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
	"emergency_contact":      "<emergency_contact>",
}

func EncryptData(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// LoadPIITagMappings loads the PII tag mappings from a JSON file.
func LoadPIITagMappings(path string) (map[string]string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mappings map[string]string
	err = json.Unmarshal(file, &mappings)
	if err != nil {
		return nil, err
	}

	return mappings, nil
}

func EncryptPIIFields(v interface{}, config ...map[string]bool) {
	val := reflect.ValueOf(v).Elem()
	typ := val.Type()

	// Use defaultConfig if config is not provided
	var useConfig map[string]bool
	if len(config) > 0 && config[0] != nil {
		useConfig = config[0]
	} else {
		useConfig = make(map[string]bool)
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		piiTag := fieldType.Tag.Get("pii")

		shouldEncrypt, configExists := useConfig[piiTag]
		if piiTag != "" && (!configExists || shouldEncrypt) && field.CanSet() {
			if field.Kind() == reflect.String {
				field.SetString(EncryptData(field.String()))
			}
		}
	}
}

// ReplacePIITags replaces PII data in the struct with placeholder tags based on the pii tags.
func ReplacePIITags(v interface{}, mappingsPath ...string) error {
	// Determine which mapping to use
	var mappings map[string]string
	if len(mappingsPath) > 0 && mappingsPath[0] != "" {
		var err error
		mappings, err = LoadPIITagMappings(mappingsPath[0])
		if err != nil {
			return err
		}
	} else {
		// Use default mappings
		mappings = DefaultPIIMappings
	}

	val := reflect.ValueOf(v).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		piiTag := fieldType.Tag.Get("pii")

		if piiTag != "" && field.CanSet() {
			// Replace the field value with the placeholder tag if it is a string
			if field.Kind() == reflect.String {
				tag, found := mappings[piiTag]
				if found {
					field.SetString(tag)
				}
			}
		}
	}

	return nil
}

// PIIHook is a custom zerolog hook for replacing PII data with placeholders.
type PIIHook struct {
	Mappings map[string]string
}

// With modifies the log event by replacing PII tags in the fields.
func (h PIIHook) With(e *zerolog.Event) *zerolog.Event {
	// We can't directly modify fields of the log event here; we need to modify the log entry at the time it's created.
	return e
}

// Run adds the PII replacement logic to the log event.
func (h PIIHook) Run(e *zerolog.Event, level zerolog.Level, message string) {
	// Map to hold updated fields
	updatedFields := make(map[string]interface{})

	// Process each field
	e.Fields(func(key string, value interface{}) {
		if strValue, ok := value.(string); ok {
			if placeholder, found := h.Mappings[strValue]; found {
				updatedFields[key] = placeholder
			} else {
				updatedFields[key] = strValue
			}
		} else {
			updatedFields[key] = value
		}
	})

	// Clear original fields and add updated fields
	e = e.Fields(nil)
	for key, value := range updatedFields {
		e.Interface(key, value)
	}
	e.Msg(message)
}

// NewPIIHook creates a new PIIHook with mappings loaded from the given path or defaults.
func NewPIIHook(mappingsPath ...string) (PIIHook, error) {
	var mappings map[string]string

	if len(mappingsPath) > 0 && mappingsPath[0] != "" {
		var err error
		mappings, err = LoadPIITagMappings(mappingsPath[0])
		if err != nil {
			return PIIHook{}, err
		}
	} else {
		mappings = DefaultPIIMappings
	}

	return PIIHook{Mappings: mappings}, nil
}

// ReplacePIITags replaces PII data in the struct with placeholder tags based on the pii tags.
// ReplacePIITags replaces PII data in the log entry with placeholder tags based on the mappings.
func (h PIIHook) ReplacePIITags(data map[string]interface{}) map[string]interface{} {
	for key, value := range data {
		if strValue, ok := value.(string); ok {
			for tag, placeholder := range h.Mappings {
				if strValue == tag {
					data[key] = placeholder
				}
			}
		}
	}
	fmt.Println(data)
	return data
}
