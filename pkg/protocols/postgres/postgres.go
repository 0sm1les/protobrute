package postgres

import (
	"context"
	"errors"
	"fmt"
	"protobrute/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type POSTGRES struct {
	version string
}

func (target POSTGRES) Brute(host string, usernames []string, passwords []string) (models.ValidCredentials, error) {
	for u := 0; u < len(usernames); u++ {
		for p := 0; p < len(passwords); p++ {
			valid, err := target.postgres(host, usernames[u], passwords[p])
			if err != nil {
				return models.ValidCredentials{}, err
			}
			if valid {
				return models.ValidCredentials{
						Host:        host,
						Protocol:    "postgres",
						Credentials: models.Credentials{Username: usernames[u], Password: passwords[p]},
					},
					nil
			}

		}
	}
	return models.ValidCredentials{}, errors.New("combinations exhausted, no valid credentials")

}

func (target POSTGRES) postgres(host string, username string, password string) (bool, error) {
	url := fmt.Sprintf("postgres://%s:%s@%s/", username, password, host)
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			//https://github.com/jackc/pgx/wiki/Error-Handling
			//handles "failed to connect to `host=172.17.0.3 user=postgres database=`: failed SASL auth (FATAL: password authentication failed for user "postgres" (SQLSTATE 28P01))"
			if pgErr.Code == "28P01" {
				return false, nil
			}
		}
		return false, err
	}
	conn.Close(context.Background())
	return true, nil
}
