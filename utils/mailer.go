package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

func SendResetCodeEmail(to string, code string) error {
	from := "no-reply@example.com"
	password := os.Getenv("MAILTRAP_PASSWORD")
	smtpHost := "sandbox.smtp.mailtrap.io"
	smtpPort := "2525"
	auth := smtp.PlainAuth("", "7e6780b85f82b9", password, smtpHost)
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: Code de réinitialisation\r\n\r\nVoici votre code : %s", to, code))

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, msg)
	if err != nil {
		return err
	}

	fmt.Println("✅ Email envoyé à Mailtrap avec succès")
	return nil
}

