package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"protobrute/models"
	"time"
)

func Handshake(host string) (response string, err error) {
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	connDL := time.Now().Add(time.Second * 2)

	conn.SetDeadline(connDL)

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			err = nil
			response = string(buffer[:n])
			return
		}
		return

	}
	response = string(buffer[:n])

	return
}

func PostValid(remoteHost string, headers map[string]string, creds models.ValidCredentials) (int, error) {
	jsonBytes, err := json.Marshal(creds)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("POST", remoteHost, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return 0, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return res.StatusCode, err
	}

	res.Body.Close()
	return res.StatusCode, nil

}
