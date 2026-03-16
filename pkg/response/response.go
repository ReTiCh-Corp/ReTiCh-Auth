package response

import (
	"encoding/json"
	"net/http"
)

type envelope map[string]any

func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func Success(w http.ResponseWriter, status int, message string, data any) {
	payload := envelope{"success": true, "message": message}
	if data != nil {
		payload["data"] = data
	}
	JSON(w, status, payload)
}

func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, envelope{"success": false, "error": message})
}

func ValidationError(w http.ResponseWriter, errors map[string]string) {
	JSON(w, http.StatusUnprocessableEntity, envelope{
		"success": false,
		"error":   "Validation failed",
		"errors":  errors,
	})
}
