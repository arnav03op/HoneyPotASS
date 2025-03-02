package main

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)


func sendAlert(message string) {
	
	smtpServer := "smtp.gmail.com:587"
	senderEmail := "arnavgupta372002@gmail.com"     
	senderPassword := "twea fswt jyec lyzx"      
	recipientEmail := "shivampoddar171@gmail.com"   
	

	
	subject := "Subject: [ALERT] Potential Attacker Detected\n"
	body := fmt.Sprintf("A potential attacker has been flagged at %s:\n\n%s", time.Now().Format("2006-01-02 15:04:05"), message)
	msg := []byte(subject + "\n" + body)

	
	auth := smtp.PlainAuth("", senderEmail, senderPassword, strings.Split(smtpServer, ":")[0])

	
	err := smtp.SendMail(smtpServer, auth, senderEmail, []string{recipientEmail}, msg)
	if err != nil {
		logrus.Errorf("Failed to send alert email: %v", err)
	} else {
		logrus.Infof("Alert email sent to %s", recipientEmail)
	}
}
