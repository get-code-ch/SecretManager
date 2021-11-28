package SecretManager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
)

const ROOT = `.SecretManager`
const DB = `vault.json`

type Vault struct {
	db      fs.File
	mac     string
	name    string
	key     string
	secrets map[string]Secret
	isDecrypted	bool
}

type Secret struct {
	Application string            `json:"application"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	Parameters  map[string]string `json:"parameters"`
}

func (v *Vault) Open() error {

	var err error
	vaultRoot := ""

	// initializing secrets array
	v.secrets = make(map[string]Secret)
	v.isDecrypted = false

	// Getting user home directory
	if vaultRoot, err = os.UserHomeDir(); err != nil {
		return err
	}

	// Creating SecretManager vault directory if not existing
	vaultRoot += `/` + ROOT
	if _, err := os.Stat(vaultRoot); os.IsNotExist(err) {
		if err := os.Mkdir(vaultRoot, 755); err != nil {
			return err
		}
		log.Printf("SecretManager vault created!\n")
	}

	// Creating SecretManager vault DB if not existing
	v.name = vaultRoot + `/` + DB
	if _, err := os.Stat(v.name); os.IsNotExist(err) {
		secrets, _ := json.Marshal(v.secrets)
		if encrypted, err := v.encrypt(secrets); err == nil {
			if err := os.WriteFile(v.name, encrypted, 0755); err != nil {
				return err
			}
		}
		log.Printf("SecretManager file created!\n")
	}

	// Getting content of vault
	if v.db, err = os.Open(v.name); err != nil {
		return err
	}

	if encrypted, err := ioutil.ReadAll(v.db); err != nil {
		return err
	} else {
		if decrypted, err := v.decrypt(encrypted); err == nil {
			if err = json.Unmarshal(decrypted, &v.secrets); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	defer v.db.Close()
	v.isDecrypted = true

	//log.Printf("Secrets --> %v", v.secrets)
	return nil
}

func (v *Vault) Close() error {
	if !v.isDecrypted {
		return errors.New("vault not open/decrypted")
	}

	secrets, _ := json.Marshal(v.secrets)
	if encrypted, err := v.encrypt(secrets); err == nil {
		if err := os.WriteFile(v.name, encrypted, 0755); err != nil {
			return err
		}
	}

	// initializing empty secrets array
	v.secrets = make(map[string]Secret)
	v.isDecrypted = false
	return nil
}

func (v *Vault) Upsert(secret Secret) error {
	v.secrets[secret.Application] = Secret{secret.Application, secret.Username, secret.Password, secret.Parameters}
	return nil
}

func (v *Vault) Read(application string) (Secret, error) {
	if s, ok := v.secrets[application]; ok {
		return s, nil
	} else {
		return Secret{}, errors.New(fmt.Sprintf("application %s, Secret not found", application))
	}
}

func (v *Vault) Delete(application string) error {
	if _,ok := v.secrets[application]; ok {
		delete(v.secrets, application)
		return nil
	} else {
		return errors.New(fmt.Sprintf("application %s, Secret not found", application))
	}
}



func (v *Vault) encrypt(decrypted []byte) ([]byte, error) {
	var privKeyFile string
	var privKey interface{}
	var err error

	if privKeyFile, err = os.UserHomeDir(); err == nil {
		privKeyFile += "/.ssh/secretmanager.key"
	} else {
		return nil, err
	}

	if b, err := ioutil.ReadFile(privKeyFile); err == nil {
		block, _ := pem.Decode(b)
		if privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
		pubKey := privKey.(*rsa.PrivateKey).PublicKey
		return rsa.EncryptPKCS1v15(rand.Reader, &pubKey, decrypted)
	} else {
		return nil, err
	}

}

func (v *Vault) decrypt(encrypted []byte) ([]byte, error) {
	var privKeyFile string
	var privKey interface{}
	var err error

	if privKeyFile, err = os.UserHomeDir(); err == nil {
		privKeyFile += "/.ssh/secretmanager.key"
	} else {
		return nil, err
	}

	if b, err := ioutil.ReadFile(privKeyFile); err == nil {
		block, _ := pem.Decode(b)
		if privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		} else {
			return rsa.DecryptPKCS1v15(rand.Reader, privKey.(*rsa.PrivateKey), encrypted)
		}
	} else {
		return nil,err
	}

}
