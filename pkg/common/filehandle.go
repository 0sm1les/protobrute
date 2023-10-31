package common

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

func ReadList(filePath string) ([]string, error) {
	var list []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		list = append(list, line)

	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(list) == 0 {
		return nil, errors.New("empty file: " + filePath)
	}

	return list, nil
}
