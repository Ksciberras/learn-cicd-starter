package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer secret"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "api key scheme without token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("GetAPIKey() err = nil, want %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Fatalf("GetAPIKey() err = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetAPIKey() unexpected err = %v", err)
			}
			if gotKey != tt.wantKey {
				t.Fatalf("GetAPIKey() = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
