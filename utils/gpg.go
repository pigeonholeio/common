package cutils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sirupsen/logrus"

	s3 "github.com/aws/aws-sdk-go-v2/service/s3"
	log "github.com/sirupsen/logrus"

	"os"

	crypto "github.com/ProtonMail/gopenpgp/v2/crypto"
)

func ExtractEmail(armoredKey string) (string, error) {
	key, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse key: %w", err)
	}

	entity := key.GetEntity()
	if entity == nil {
		return "", fmt.Errorf("no entity found in key")
	}

	if len(entity.Identities) == 1 {
		for _, ident := range entity.Identities {
			return ident.UserId.Email, nil
		}
	}
	return "", fmt.Errorf("more than one identity found")
}

func CreateGPGKeyPair(name string, email string) (publicKey, privateKey, fingerprint string) {
	logrus.Debugln("Attempting to generate RSA secret")
	key, err := crypto.GenerateKey(name, email, "x25519", 0)
	if err != nil {
		logrus.Debugf("Error with GenerateKey: %s", err.Error())
		return
	}
	// crypto.GenerateKey((name,email))

	logrus.Debugln("Retrieving public key Armor with custom headers")
	pubKey, err := key.GetArmoredPublicKeyWithCustomHeaders("https://pigeono.io", "PigeonHole v1.0")
	if err != nil {
		logrus.Debugf("Error with ArmorWithCustomHeaders: %s", err.Error())
		return
	}
	logrus.Debugln("Retrieving private key Armor with custom headers")
	privKey, err := key.ArmorWithCustomHeaders("https://pigeono.io", "PigeonHole v1.0")
	logrus.Debugf("Created GPG key with fingerprint: %s\n", key.GetFingerprint())
	return pubKey, privKey, key.GetSHA256Fingerprint()
}

func EncryptFile(filePath string, armoredPubKeys []string) (encryptedFilePath string, err error) {
	var publicKeyRing *crypto.KeyRing

	for _, armoredPubKey := range armoredPubKeys {
		publicKeyObj, err := crypto.NewKeyFromArmored(armoredPubKey)
		if err != nil {
			return "", err
		}

		if publicKeyRing == nil {
			publicKeyRing, err = crypto.NewKeyRing(publicKeyObj)
			if err != nil {
				return "", err
			}
		} else {
			err = publicKeyRing.AddKey(publicKeyObj)
			if err != nil {
				return "", err
			}
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	pr, pw := io.Pipe()
	defer pw.Close()

	messageMeta := crypto.PlainMessageMetadata{
		IsBinary: true,
		Filename: filePath,
		ModTime:  32423423, // Consider using a meaningful value or parameter for ModTime
	}

	tmpFile, err := ioutil.TempFile(os.TempDir(), "pigeonhole")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	go func() {
		defer pw.Close()
		pt, err := publicKeyRing.EncryptStream(pw, &messageMeta, nil)
		if err != nil {
			log.Println(err)
			return
		}

		if _, err := io.Copy(pt, file); err != nil {
			log.Println(err)
			return
		}
		pt.Close()
	}()

	if _, err = io.Copy(tmpFile, pr); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}
func DecryptBytes(input []byte, destinationPath *string, armoredPrivKey *string) (decryptedFilePath string, err error) {

	keyObj, err := crypto.NewKeyFromArmored(*armoredPrivKey)
	if err != nil {
		return "", err
	}

	privKeyRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return "", err
	}
	os.MkdirAll(*destinationPath, os.ModePerm)

	tmpFile, err := ioutil.TempFile(*destinationPath, "pigeonhole-")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Open a file for writing the decrypted data

	fwrite, err := os.OpenFile(tmpFile.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer fwrite.Close()
	reader := bytes.NewReader(input)

	// Decrypt the data from the input reader
	decryptReader, err := privKeyRing.DecryptStream(reader, nil, 0)
	if err != nil {
		os.RemoveAll(tmpFile.Name())
		return "", err
	}

	// Copy the decrypted data to the file
	_, err = io.Copy(fwrite, decryptReader)
	if err != nil {
		os.RemoveAll(tmpFile.Name())
		return "", err
	}

	// Close the file
	err = fwrite.Close()
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

func EncryptStream(src io.Reader, dst io.Writer, armoredPubKeys []string) error {
	var pubRing *crypto.KeyRing

	for _, armoredKey := range armoredPubKeys {
		keyObj, err := crypto.NewKeyFromArmored(armoredKey)
		if err != nil {
			return err
		}
		if pubRing == nil {
			pubRing, err = crypto.NewKeyRing(keyObj)
			if err != nil {
				return err
			}
		} else if err := pubRing.AddKey(keyObj); err != nil {
			return err
		}
	}

	pt, err := pubRing.EncryptStream(dst, &crypto.PlainMessageMetadata{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	defer pt.Close()

	_, err = io.Copy(pt, src)
	return err
}

// DecryptStream decrypts data from `src` into `dst` using the given private key.
func DecryptStream(src io.Reader, dst io.Writer, armoredPrivKey string) error {
	keyObj, err := crypto.NewKeyFromArmored(armoredPrivKey)
	if err != nil {
		return err
	}
	privRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return err
	}

	decryptReader, err := privRing.DecryptStream(src, nil, 0)
	if err != nil {
		return err
	}
	// defer decryptReader.Close()

	_, err = io.Copy(dst, decryptReader)
	return err
}

func ReEncryptS3Object(
	ctx context.Context,
	s3Client *s3.Client,
	bucket, key string,
	privKey string,
	pubKeys []string,
	out io.Writer,
) error {

	// Download object as stream
	obj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return err
	}
	defer obj.Body.Close()

	// Create streaming pipeline: decrypt → encrypt
	prDecrypt, pwDecrypt := io.Pipe()
	prEncrypt, pwEncrypt := io.Pipe()

	// Stage 1: decrypt S3 object
	go func() {
		defer pwDecrypt.Close()
		if err := DecryptStream(obj.Body, pwDecrypt, privKey); err != nil {
			pwDecrypt.CloseWithError(err)
		}
	}()

	// Stage 2: encrypt decrypted output
	go func() {
		defer pwEncrypt.Close()
		if err := EncryptStream(prDecrypt, pwEncrypt, pubKeys); err != nil {
			pwEncrypt.CloseWithError(err)
		}
	}()

	// Stage 3: stream to output (could be file or another S3 upload)
	_, err = io.Copy(out, prEncrypt)
	return err
}

func ReEncryptAndUploadToS3(
	ctx context.Context,
	s3Client *s3.Client,
	bucket, key string,
	encryptedData []byte,
	privKey string,
	pubKeys []string,
) error {
	src := bytes.NewReader(encryptedData)

	// Pipes: src -> decrypt -> encrypt -> upload
	prDecrypt, pwDecrypt := io.Pipe()
	prEncrypt, pwEncrypt := io.Pipe()

	// Stage 1: decrypt
	go func() {
		defer pwDecrypt.Close()
		if err := DecryptStream(src, pwDecrypt, privKey); err != nil {
			pwDecrypt.CloseWithError(err)
		}
	}()

	// Stage 2: encrypt
	go func() {
		defer pwEncrypt.Close()
		if err := EncryptStream(prDecrypt, pwEncrypt, pubKeys); err != nil {
			pwEncrypt.CloseWithError(err)
		}
	}()

	// Stage 3: upload encrypted stream to S3
	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   prEncrypt,
	})
	return err
}
