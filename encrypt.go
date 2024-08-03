package piishield

import (
	"reflect"
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

// Redact returns a new instance of the struct with PII tags replaced for display purposes
func Redact(v interface{}) interface{} {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	return redactValue(val)
}

// redactValue recursively redacts values in structs, maps, slices, and arrays
func redactValue(val reflect.Value) interface{} {
	switch val.Kind() {
	case reflect.Struct:
		return redactStruct(val)
	case reflect.Map:
		redactedMap := reflect.MakeMap(val.Type())
		for _, key := range val.MapKeys() {
			redactedMap.SetMapIndex(key, reflect.ValueOf(redactValue(val.MapIndex(key))))
		}
		return redactedMap.Interface()
	case reflect.Slice, reflect.Array:
		redactedSlice := reflect.MakeSlice(val.Type(), val.Len(), val.Cap())
		for i := 0; i < val.Len(); i++ {
			redactedSlice.Index(i).Set(reflect.ValueOf(redactValue(val.Index(i))))
		}
		return redactedSlice.Interface()
	default:
		return val.Interface()
	}
}

// redactStruct redacts fields in a struct
func redactStruct(val reflect.Value) interface{} {
	typ := val.Type()
	redacted := reflect.New(typ).Elem()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		if placeholder, found := DefaultPIIMappings[fieldType.Tag.Get("pii")]; found {
			redacted.Field(i).SetString(placeholder)
		} else {
			redacted.Field(i).Set(reflect.ValueOf(redactValue(field)))
		}
	}

	return redacted.Interface()
}
