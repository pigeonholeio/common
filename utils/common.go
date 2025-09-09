package utils

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pallinder/go-randomdata"

	gout "github.com/drewstinnett/gout/v2"
	"github.com/drewstinnett/gout/v2/formats"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func DisplayHelp(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		cmd.Help()
		os.Exit(0)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {

	return f(req)
}

func ArrOutputData(data *[]interface{}) {
	for i, s := range *data {
		logrus.Debug(i)
		OutputData(s)
	}
}

func OutputData(data interface{}) {
	// x := getOutputFormatter()
	g := gout.New()
	// spew.Dump(oidcProviders.JSON200.OidcProviders)
	for formatN, formatG := range formats.Formats {
		fmt.Println(formatN, formatG)
		g.SetFormatter(formatG())
		g.MustPrint(data)
	}
}

func decodeJWT(tokenStr string) (map[string]interface{}, error) {
	// Splitting the token into parts
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token received")
	}

	// Decode the payload part (second part)
	payload, err := jwt.NewParser().DecodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding token: %v", err)
	}

	// Unmarshal the JSON payload into a map
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling token payload: %v", err)
	}

	return claims, nil
}

func DecodePigeonHoleJWT(accessToken string) (map[string]interface{}, error) {
	return decodeJWT(accessToken)
}

// EncodeToBase64 takes a string and returns its base64 encoded version
func EncodeToBase64(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return encoded
}
func DecodeFromBase64(input string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}

func GenerateCodeWord(numWords int) string {
	words := make([]string, numWords+1)
	// words[0] = randomdata.Adjective()
	words[0] = randomdata.Adjective()
	for i := 0; i < numWords; i++ {
		words[i+1] = randomdata.Noun()
	}

	return strings.Join(words, "-")
}

func SecureDelete(filePath string) error {
	// Open the file
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size
	info, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := info.Size()

	// Overwrite the file with random data
	data := make([]byte, fileSize)
	_, err = rand.Read(data) // You can also use zeros instead of random data
	if err != nil {
		return err
	}
	_, err = file.WriteAt(data, 0)
	if err != nil {
		return err
	}

	// Truncate the file (optional)
	err = file.Truncate(0)
	if err != nil {
		return err
	}

	// Close the file before deleting
	err = file.Close()
	if err != nil {
		return err
	}

	// Delete the file
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

func CompressPath(src string, buf io.Writer) error {
	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	// is file a folder?
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	mode := fi.Mode()
	if mode.IsRegular() {
		// get header
		header, err := tar.FileInfoHeader(fi, src)
		if err != nil {
			return err
		}
		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// get content
		data, err := os.Open(src)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, data); err != nil {
			return err
		}
	} else if mode.IsDir() { // folder

		// walk through every file in the folder
		filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
			// generate tar header
			header, err := tar.FileInfoHeader(fi, file)
			if err != nil {
				return err
			}

			// must provide real name
			// (see https://golang.org/src/archive/tar/utils.go?#L626)
			header.Name = filepath.ToSlash(file)

			// write header
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			// if not a dir, write file content
			if !fi.IsDir() {
				data, err := os.Open(file)
				if err != nil {
					return err
				}
				if _, err := io.Copy(tw, data); err != nil {
					return err
				}
			}
			return nil
		})
	} else {
		return fmt.Errorf("error: file type not supported")
	}

	// produce tar
	if err := tw.Close(); err != nil {
		return err
	}
	// produce gzip
	if err := zr.Close(); err != nil {
		return err
	}
	//
	return nil
}

func DecompressFile(src string, dst string) error {
	// ungzip
	file, _ := os.OpenFile(src, os.O_RDONLY, os.ModePerm)
	zr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	// untar
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}
		target := header.Name

		// add dst + re-format slashes according to system
		target = filepath.Join(dst, header.Name)

		// check the type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it (with 0755 permission)
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		// if it's a file create it (with same permission)
		case tar.TypeReg:
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			if _, err := io.Copy(fileToWrite, tr); err != nil {
				return err
			}

			fileToWrite.Close()
		}
	}

	//
	return nil
}

func ShredFile(path string) error {
	return os.Remove(path)
}

func KeysExist() bool {
	if viper.GetString("key.latest.private") != "" {
		return true
	}
	return false
}
