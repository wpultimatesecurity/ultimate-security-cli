package api

import "fmt"

type ErrorKind int

const (
	ErrKindNetwork ErrorKind = iota
	ErrKindAuth
	ErrKindPluginMissing
	ErrKindAPI
	ErrKindTimeout
	ErrKindValidation
)

type Error struct {
	Kind    ErrorKind
	Message string
	Status  int
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

func NetworkError(msg string, err error) *Error {
	return &Error{Kind: ErrKindNetwork, Message: msg, Err: err}
}

func AuthError(status int, msg string) *Error {
	return &Error{Kind: ErrKindAuth, Message: msg, Status: status}
}

func PluginMissingError(msg string) *Error {
	return &Error{Kind: ErrKindPluginMissing, Message: msg}
}

func APIError(status int, msg string) *Error {
	return &Error{Kind: ErrKindAPI, Message: msg, Status: status}
}

func TimeoutError(msg string, err error) *Error {
	return &Error{Kind: ErrKindTimeout, Message: msg, Err: err}
}

func ValidationError(msg string) *Error {
	return &Error{Kind: ErrKindValidation, Message: msg}
}

func IsAuth(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Kind == ErrKindAuth
	}
	return false
}

func IsPluginMissing(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Kind == ErrKindPluginMissing
	}
	return false
}

func IsNetwork(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Kind == ErrKindNetwork
	}
	return false
}

func IsTimeout(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Kind == ErrKindTimeout
	}
	return false
}
