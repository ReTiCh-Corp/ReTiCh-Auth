package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSON(t *testing.T) {
	w := httptest.NewRecorder()
	JSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("expected key=value, got %v", got)
	}
}

func TestSuccess_WithData(t *testing.T) {
	w := httptest.NewRecorder()
	Success(w, http.StatusCreated, "created", map[string]string{"id": "123"})

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got["success"] != true {
		t.Error("expected success=true")
	}
	if got["message"] != "created" {
		t.Errorf("expected message=created, got %v", got["message"])
	}
	if got["data"] == nil {
		t.Error("expected data to be present")
	}
}

func TestSuccess_WithoutData(t *testing.T) {
	w := httptest.NewRecorder()
	Success(w, http.StatusOK, "ok", nil)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if _, ok := got["data"]; ok {
		t.Error("expected data to be absent when nil")
	}
}

func TestError(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, http.StatusUnauthorized, "unauthorized")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got["success"] != false {
		t.Error("expected success=false")
	}
	if got["error"] != "unauthorized" {
		t.Errorf("expected error=unauthorized, got %v", got["error"])
	}
}

func TestValidationError(t *testing.T) {
	w := httptest.NewRecorder()
	ValidationError(w, map[string]string{"email": "invalid email", "name": "required"})

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", w.Code)
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got["success"] != false {
		t.Error("expected success=false")
	}
	if got["error"] != "Validation failed" {
		t.Errorf("expected error=Validation failed, got %v", got["error"])
	}
	errs, ok := got["errors"].(map[string]any)
	if !ok {
		t.Fatal("expected errors to be a map")
	}
	if errs["email"] != "invalid email" {
		t.Errorf("expected email error, got %v", errs["email"])
	}
}
