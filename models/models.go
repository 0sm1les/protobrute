package models

import "fmt"

type Options struct {
	TargetFile    string
	UsernameFile  string
	PasswordsFile string
	Threads       int
	Protocol      string
	AutoDetect    bool
	Outfile       string
	ParentHost    string
	HeaderString  string
}

type ValidCredentials struct {
	Host        string
	Protocol    string
	Credentials Credentials
}

type Credentials struct {
	Username string
	Password string
}

func (info ValidCredentials) ToString() string {
	return fmt.Sprintf("host:%s protocol:%s username:%s password:%s", info.Host, info.Protocol, info.Credentials.Username, info.Credentials.Password)
}
