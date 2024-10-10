// internal/config/config.go

package config

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/sethvargo/go-envconfig"
)

var ErrEnvNotSet = errors.New("environment variable is not set")

// CheckConfig checks if all required fields are set.
func CheckConfig(c interface{}) error {
	value := reflect.ValueOf(c)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	structType := value.Type()

	for fieldIndex := range structType.NumField() {
		field := value.Field(fieldIndex)
		fieldType := field.Type()
		fieldKind := fieldType.Kind()
		envTag := structType.Field(fieldIndex).Tag.Get("env")

		if fieldKind == reflect.Ptr {
			if field.IsNil() {
				// Init nested structure if it is nil
				field.Set(reflect.New(fieldType.Elem()))
			}
			// Recursively check nested structure
			if err := CheckConfig(field.Interface()); err != nil {
				return err
			}
		} else if envTag != "" && fieldKind == reflect.String && field.String() == "" {
			return fmt.Errorf("%w: %s", ErrEnvNotSet, envTag)
		}
	}

	return nil
}

// SetupConfig loads configuration from environment variables.
func SetupConfig(ctx context.Context) (*Config, error) {
	var cfg Config

	if err := envconfig.Process(ctx, &cfg); err != nil {
		return nil, fmt.Errorf("failed to process env config: %w", err)
	}

	if err := CheckConfig(&cfg); err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	return &cfg, nil
}
