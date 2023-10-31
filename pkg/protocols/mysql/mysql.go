package mysql

import (
	"database/sql"
	"errors"
	"fmt"
	"protobrute/models"
	"strings"

	"github.com/go-sql-driver/mysql"
)

type MYSQL struct {
	version string
}

func Detect(banner string) (MYSQL, error) {
	banner = strings.ToLower(banner)
	if strings.Contains(banner, "mysql") || strings.Contains(banner, "mariadb") {
		return MYSQL{}, nil
	}
	return MYSQL{}, errors.New("not mysql")
}

func (target MYSQL) Brute(host string, usernames []string, passwords []string) (models.ValidCredentials, error) {
	for u := 0; u < len(usernames); u++ {
		for p := 0; p < len(passwords); p++ {
			valid, err := target.mysql(host, usernames[u], passwords[p])
			if err != nil {
				return models.ValidCredentials{}, err
			}
			if valid {
				return models.ValidCredentials{
						Host:        host,
						Protocol:    "mysql",
						Credentials: models.Credentials{Username: usernames[u], Password: passwords[p]},
					},
					nil
			}
		}
	}
	return models.ValidCredentials{}, errors.New("combinations exhausted, no valid credentials")
}

func (target MYSQL) mysql(host string, username string, password string) (bool, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/", username, password, host))
	if err != nil {
		return false, err
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		var sqErr *mysql.MySQLError
		if errors.As(err, &sqErr) {
			//handles "Error 1045 (28000): Access denied for user 'admin'@'172.17.0.1' (using password: YES)"
			if sqErr.Number == 1045 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}
