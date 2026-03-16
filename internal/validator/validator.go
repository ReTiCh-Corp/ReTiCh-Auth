package validator

import (
	"encoding/json"
	"io"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// Decode decodes the JSON body into dst and validates it.
// Returns a map of field→message on validation error, nil otherwise.
func Decode(body io.Reader, dst any) (map[string]string, error) {
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		return nil, err
	}

	if err := validate.Struct(dst); err != nil {
		return formatErrors(err.(validator.ValidationErrors)), nil
	}

	return nil, nil
}

func formatErrors(errs validator.ValidationErrors) map[string]string {
	out := make(map[string]string, len(errs))
	for _, e := range errs {
		field := strings.ToLower(e.Field())
		out[field] = fieldMessage(e)
	}
	return out
}

func fieldMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email address"
	case "min":
		return "Too short (min " + e.Param() + " characters)"
	case "max":
		return "Too long (max " + e.Param() + " characters)"
	case "eqfield":
		return "Does not match " + strings.ToLower(e.Param())
	default:
		return "Invalid value"
	}
}

// specialChars are the accepted special characters for passwords.
const specialChars = `!@#$%^&*()_+-=[]{}|;':",.<>?/~-` + "`\\"

// StrongPassword returns an error message if the password doesn't meet requirements.
// Rules: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special character.
func StrongPassword(password string) string {
	if len(password) < 8 {
		return "Password must be at least 8 characters"
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case strings.ContainsRune(specialChars, c):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return "Password must contain at least one uppercase letter"
	}
	if !hasLower {
		return "Password must contain at least one lowercase letter"
	}
	if !hasDigit {
		return "Password must contain at least one digit"
	}
	if !hasSpecial {
		return `Password must contain at least one special character (!@#$%^&*-_+=.,?...)`
	}
	return ""
}
