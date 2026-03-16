package emailservice

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"time"

	"github.com/resend/resend-go/v2"
)

//go:embed templates/*.html
var templateFS embed.FS

type EmailService struct {
	client    *resend.Client
	fromEmail string
	fromName  string
	templates *template.Template
}

func NewEmailService(apiKey, fromEmail, fromName string) (*EmailService, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing email templates: %w", err)
	}

	return &EmailService{
		client:    resend.NewClient(apiKey),
		fromEmail: fromEmail,
		fromName:  fromName,
		templates: tmpl,
	}, nil
}

func (s *EmailService) send(to, subject, templateName string, data any) error {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, templateName, data); err != nil {
		return fmt.Errorf("rendering template %q: %w", templateName, err)
	}

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail),
		To:      []string{to},
		Subject: subject,
		Html:    buf.String(),
	}

	_, err := s.client.Emails.Send(params)
	return err
}

func (s *EmailService) SendVerificationEmail(to, verifyURL string) error {
	return s.send(to, "Vérifiez votre adresse email", "verify_email.html", map[string]string{
		"VerifyURL": verifyURL,
	})
}

func (s *EmailService) SendPasswordResetEmail(to, resetURL string) error {
	return s.send(to, "Réinitialisation de votre mot de passe", "reset_password.html", map[string]string{
		"ResetURL": resetURL,
	})
}

func (s *EmailService) SendMagicLinkEmail(to, magicURL string) error {
	return s.send(to, "Votre lien de connexion", "magic_link.html", map[string]string{
		"MagicURL": magicURL,
	})
}

func (s *EmailService) SendPasswordChangedEmail(to string) error {
	return s.send(to, "Votre mot de passe a été modifié", "password_changed.html", map[string]string{
		"ChangedAt": time.Now().UTC().Format("02/01/2006 à 15:04 UTC"),
	})
}
