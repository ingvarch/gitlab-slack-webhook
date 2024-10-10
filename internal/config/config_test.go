package config_test

import (
	"testing"

	"github.com/ingvarch/gitlab-slack-webhook/internal/config"
)

func TestCheckConfig(t *testing.T) {
	t.Parallel()

	type testStruct struct {
		RequiredField string `env:"REQUIRED_FIELD"`
		OptionalField string
	}

	tests := []struct {
		name    string
		config  testStruct
		wantErr bool
	}{
		{
			name: "All required fields set",
			config: testStruct{
				RequiredField: "set",
				OptionalField: "optional",
			},
			wantErr: false,
		},
		{
			name: "Required field not set",
			config: testStruct{
				RequiredField: "",
				OptionalField: "optional",
			},
			wantErr: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := config.CheckConfig(&testCase.config)

			if (err != nil) != testCase.wantErr {
				t.Errorf("CheckConfig() error = %v, wantErr %v", err, testCase.wantErr)
			}
		})
	}
}
