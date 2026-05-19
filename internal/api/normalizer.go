package api

import (
	"encoding/json"
	"fmt"
)

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"msg"`
}

type envelopeWithData struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
}

type envelopeWithMessage struct {
	Success bool            `json:"success"`
	Message string          `json:"msg"`
	Data    json.RawMessage `json:"data"`
}

func UnwrapEnvelope(raw []byte) (json.RawMessage, error) {
	var e envelopeWithData
	if err := json.Unmarshal(raw, &e); err != nil {
		return raw, nil
	}

	if !e.Success {
		var em envelopeWithMessage
		if json.Unmarshal(raw, &em) == nil && em.Message != "" {
			return nil, fmt.Errorf("API error: %s", em.Message)
		}
		return nil, fmt.Errorf("API returned success=false")
	}

	if e.Data != nil {
		return e.Data, nil
	}

	return raw, nil
}

func DecodeResponse(raw []byte, target interface{}) error {
	data, err := UnwrapEnvelope(raw)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("empty response data")
	}
	return json.Unmarshal(data, target)
}

func DecodeDirect(raw []byte, target interface{}) error {
	return json.Unmarshal(raw, target)
}
