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
    httpClient := &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
        },
    }

	if host != nil {
		c.HostURL = *host
	}

	// If username or password not provided, return empty client
	if username == nil || password == nil {
		return &c, nil
	}

	return &ForwardNetworksClient{
		HostURL:    host,
		Username:   username,
		Password:   password,
		Insecure:   insecure,
		HttpClient: httpClient,
	}
}


func (c *ForwardNetworksClient) GetVersion() (string, error) {
	url := fmt.Sprintf("%s/api/version", c.BaseURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(c.Username, c.Password)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var versionData struct {
		Version string `json:"version"`
	}
	err = json.Unmarshal(bodyBytes, &versionData)
	if err != nil {
		return "", err
	}

	return versionData.Version, nil
}

