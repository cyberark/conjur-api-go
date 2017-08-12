package conjurapi

import (
	"net/http"
	"time"
)

type client struct {
	config     Config
	AuthToken  string
	httpclient *http.Client
}

func NewClient(c Config) (*client, error) {
	valid, error := c.IsValid()

	if !valid {
		return nil, error
	}

	return &client{
		config:     c,
		httpclient: &http.Client{
			Timeout: time.Second * 10,
		},
	}, nil
}
