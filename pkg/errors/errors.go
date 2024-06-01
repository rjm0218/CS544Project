package errHand

import "log"

func LogError(err error, message string) error {
	if err != nil {
		log.Printf("[error] %s: %v", message, err)
	}
	return err
}
