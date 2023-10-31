package ftp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"protobrute/models"
	"strings"
	"time"
)

type FTP struct {
	version string
}

func Detect(banner string) (FTP, error) {
	banner = strings.ToLower(banner)
	if strings.Contains(banner, "ftp") {
		return FTP{}, nil
	}
	return FTP{}, errors.New("not ftp")
}

func (target FTP) Brute(host string, usernames []string, passwords []string) (models.ValidCredentials, error) {
	for u := 0; u < len(usernames); u++ {
		for p := 0; p < len(passwords); p++ {
			valid, err := target.ftp(host, usernames[u], passwords[p])
			if err != nil {
				return models.ValidCredentials{}, err
			}
			if valid {
				return models.ValidCredentials{
						Host:        host,
						Protocol:    "ftp",
						Credentials: models.Credentials{Username: usernames[u], Password: passwords[p]},
					},
					nil
			}
		}
	}
	return models.ValidCredentials{}, errors.New("combinations exhausted, no valid credentials")
}

func (target FTP) ftp(host string, username string, password string) (bool, error) {
	// remember setDeadLine in the conn package
	conn, err := net.DialTimeout("tcp", host, time.Second*2)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	sendCommand := func(command string) (string, error) {
		_, err = conn.Write([]byte(command))
		if err != nil {
			return "", err
		}
		response, _ := bufio.NewReader(conn).ReadString(' ')
		return response, nil
	}

	// this is nessesary because even when sending a command, the reader will not always get the response in order
	Limit := 3
	Count := 0
	for {
		if Count > Limit {
			break
		}
		respCode, err := sendCommand(fmt.Sprintf("USER %s\n", username))
		if err != nil {
			return false, err
		}
		if !strings.Contains(respCode, "331") {
			Count++
			continue
		}
		for {
			if Count > Limit {
				break
			}
			respCode, err = sendCommand(fmt.Sprintf("PASS %s\n", password))
			if err != nil {
				return false, err
			}
			if strings.Contains(respCode, "331") {
				Count++
				continue
			}
			return strings.Contains(respCode, "230"), nil

		}
	}
	return false, nil
}
