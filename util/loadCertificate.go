package util

import (
	"io/ioutil"
	"regexp"
	"strings"
)

var (
	re = regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
)

// LoadCertificate from file system
func LoadCertificate(certPath string) (string, error) {
	b, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	return SanitizeCertificate(string(b)), nil
}

func SanitizeCertificate(cert string) string {
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\n", "", -1)
	return cert
}
