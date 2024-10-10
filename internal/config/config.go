// internal/config/config.go

package config

import (
	"context"
	"fmt"
	"reflect"

	"github.com/sethvargo/go-envconfig"
)

// checkConfig checks if all required fields are set
func checkConfig(c interface{}) error {
	v := reflect.ValueOf(c)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := field.Type()
		fieldKind := fieldType.Kind()
		tag := t.Field(i).Tag.Get("env")

		if fieldKind == reflect.Ptr {
			if field.IsNil() {
				// Init nested structure if it is nil
				field.Set(reflect.New(fieldType.Elem()))
			}
			// Recursively check nested structure
			if err := checkConfig(field.Interface()); err != nil {
				return err
			}
		} else if tag != "" && fieldKind == reflect.String && field.String() == "" {
			return fmt.Errorf("environment variable %s is not set", tag)
		}
	}
	return nil
}

// SetupConfig loads configuration from environment variables
func SetupConfig(ctx context.Context) (*Config, error) {
	var cfg Config

	if err := envconfig.Process(ctx, &cfg); err != nil {
		return nil, fmt.Errorf("failed to process env config: %w", err)
	}

	if err := checkConfig(&cfg); err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	return &cfg, nil
}
