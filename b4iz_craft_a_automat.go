package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

type Notification struct {
	ID        string
	Message   string
	Severity  string
	Timestamp time.Time
}

type SecurityToolNotifier struct {
	apiKey    string
	apiSecret string
	endpoint  string
}

func NewSecurityToolNotifier(apiKey, apiSecret, endpoint string) *SecurityToolNotifier {
	return &SecurityToolNotifier{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		endpoint:  endpoint,
	}
}

func (n *SecurityToolNotifier) SendNotification(message string, severity string) error {
	noti := &Notification{
		ID:        uuid.New().String(),
		Message:   message,
		Severity:  severity,
		Timestamp: time.Now(),
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", n.endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", n.apiKey))
	req.Header.Set("Content-Type", "application/json")

	err = json.NewEncoder(req.Body).Encode(noti)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return nil
}

func main() {
	notifier := NewSecurityToolNotifier(
		os.Getenv("API_KEY"),
		os.Getenv("API_SECRET"),
		os.Getenv("ENDPOINT"),
	)

	err := notifier.SendNotification("Suspicious activity detected", "HIGH")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Notification sent successfully!")
}