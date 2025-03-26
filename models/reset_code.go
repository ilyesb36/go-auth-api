
package models

import "time"

type ResetCode struct {
	ID        int
	Email     string
	Code      string
	ExpiresAt time.Time
}