package forwardnetworks

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const HostURL string = "https://fwd.app"

type Client struct {
	Username string
	Password string
	HostURL  string
	Insecure bool
	HttpClient *http.Client
}

func NewClient(host, username, password *string, insecure bool) (*Client, error) {
    c := Client{
        HTTPClient: &http.Client{
            Timeout: 10 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
            },
        },
        // Default Hashicups URL
        HostURL: HostURL,
    }

    if host != nil {
        c.HostURL = *host
    }
	
    if username == nil || password == nil {
		return &c, nil
	}

    if username != nil {
        c.Username = *username
    }

    if password != nil {
        c.Password = *password
    }



    return &c, nil
}
