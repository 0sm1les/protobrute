package ssh

import (
	"errors"
	"net"
	"protobrute/models"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSH struct {
	version string
}

func Detect(banner string) (SSH, error) {
	banner = strings.ToLower(banner)
	if strings.Contains(banner, "ssh") {
		return SSH{}, nil
	}
	return SSH{}, errors.New("not ssh")
}

func (target SSH) Brute(host string, usernames []string, passwords []string) (models.ValidCredentials, error) {
	for u := 0; u < len(usernames); u++ {
		for p := 0; p < len(passwords); p++ {
			valid, err := target.ssh(host, usernames[u], passwords[p])
			if err != nil {
				return models.ValidCredentials{}, err
			}
			if valid {
				return models.ValidCredentials{
						Host:        host,
						Protocol:    "ssh",
						Credentials: models.Credentials{Username: usernames[u], Password: passwords[p]},
					},
					nil
			}
		}
	}
	return models.ValidCredentials{}, errors.New("combinations exhausted, no valid credentials")
}

func (target SSH) ssh(host string, username string, password string) (bool, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * 2,
	}

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		if err.Error() == "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain" {
			return false, nil
		}
		return false, err
	}
	defer client.Close()
	session, err := client.NewSession()

	if err != nil {
		return false, err
	}

	defer session.Close()
	return true, nil
}
