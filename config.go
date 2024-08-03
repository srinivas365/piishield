package piishield

func NewConfig(settings map[string]bool) map[string]bool {
	config := make(map[string]bool)
	for k, v := range settings {
		config[k] = v
	}
	return config
}
