package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		wantKey     string
		wantErr     error
		wantErrText string
	}{
		{
			name:    "valid api key",
			header:  "ApiKey mysecretkey123",
			wantKey: "mysecretkey123",
		},
		{
			name:    "no authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong scheme",
			header:      "Bearer sometoken",
			wantErrText: "malformed authorization header",
		},
		{
			name:        "missing key value",
			header:      "ApiKey",
			wantErrText: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			got, err := GetAPIKey(headers)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("got err %v, want %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErrText != "" {
				if err == nil || err.Error() != tt.wantErrText {
					t.Errorf("got err %v, want %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("got key %q, want %q", got, tt.wantKey)
			}
		})
	}
}
