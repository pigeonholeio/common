package utils

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/sirupsen/logrus"
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
