package models

import "time"

type Expired struct {
	ID        uint   `json:"id"`
	UserID    int `json:"userId"`
	Token     string `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}
