package piishield

import (
	"reflect"
)

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
