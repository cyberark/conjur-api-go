package conjurapi

import (
	"net/http"
	"time"
)

type client struct {
	config     Config
	authToken  AuthnToken
	httpclient *http.Client
}

func NewClient(c Config) (*client, error) {
	var (
		err error
	)

	err = c.validate()

	if err != nil {
		return nil, err
	}

	return &client{
		config:     c,
		httpclient: &http.Client{
			Timeout: time.Second * 10,
		},
	}, nil
}
