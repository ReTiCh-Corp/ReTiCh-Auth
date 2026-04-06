package validator

import (
	"strings"
	"testing"
)

func TestStrongPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid strong password", "Secure@123", false},
		{"too short", "Ab1!", true},
		{"no uppercase", "secure@123", true},
		{"no lowercase", "SECURE@123", true},
		{"no digit", "Secure@abc", true},
		{"no special char", "Secure1234", true},
		{"exactly 8 chars valid", "Aa1!abcd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := StrongPassword(tt.password)
			if tt.wantErr && msg == "" {
				t.Errorf("expected error for password %q, got none", tt.password)
			}
			if !tt.wantErr && msg != "" {
				t.Errorf("expected no error for password %q, got: %s", tt.password, msg)
			}
		})
	}
}

func TestDecode_Valid(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"required,email"`
		Name  string `json:"name"  validate:"required"`
	}

	body := strings.NewReader(`{"email":"test@example.com","name":"Alice"}`)
	var dst payload
	errs, err := Decode(body, &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errs != nil {
		t.Fatalf("unexpected validation errors: %v", errs)
	}
	if dst.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", dst.Email)
	}
}

func TestDecode_InvalidJSON(t *testing.T) {
	body := strings.NewReader(`not json`)
	var dst struct{ Email string `json:"email"` }
	_, err := Decode(body, &dst)
	if err == nil {
		t.Fatal("expected JSON decode error, got nil")
	}
}

func TestDecode_ValidationErrors(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"required,email"`
	}

	body := strings.NewReader(`{"email":"not-an-email"}`)
	var dst payload
	errs, err := Decode(body, &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errs == nil {
		t.Fatal("expected validation errors, got nil")
	}
	if _, ok := errs["email"]; !ok {
		t.Error("expected 'email' in validation errors")
	}
}

func TestDecode_MissingRequired(t *testing.T) {
	type payload struct {
		Email string `json:"email" validate:"required"`
	}

	body := strings.NewReader(`{}`)
	var dst payload
	errs, err := Decode(body, &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errs == nil {
		t.Fatal("expected validation errors, got nil")
	}
	if msg, ok := errs["email"]; !ok || msg == "" {
		t.Error("expected 'email' validation error for missing required field")
	}
}
