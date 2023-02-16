package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	mrand "math/rand"
	"os"
	"scaling_manager/config"
	"scaling_manager/logger"
	osutils "scaling_manager/opensearchUtils"
	utils "scaling_manager/utilities"
	"strings"
	"time"
)

var log = new(logger.LOG)
var EncryptionSecret string
var seed = time.Now().Unix()
var SecretFilepath = ".secret.txt"

// Initializing logger module
func init() {
	var osAdminPassword, osAdminUsername string
	log.Init("logger")
	log.Info.Println("Crypto module initiated")
	mrand.Seed(seed)
	configStruct, _ := config.GetConfig()
	if _, err := os.Stat(SecretFilepath); err == nil {
		EncryptionSecret = GetEncryptionSecret()
		osAdminUsername = GetDecryptedData(configStruct.ClusterDetails.OsCredentials.OsAdminUsername)
		osAdminPassword = GetDecryptedData(configStruct.ClusterDetails.OsCredentials.OsAdminPassword)
	} else {
		osAdminUsername = configStruct.ClusterDetails.OsCredentials.OsAdminUsername
		osAdminPassword = configStruct.ClusterDetails.OsCredentials.OsAdminPassword
	}

	osutils.InitializeOsClient(osAdminUsername, osAdminPassword)
	UpdateSecretAndEncryptCreds(true, configStruct)
}

// bytes is used when creating ciphers for the string
var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

// Generate a random string of length 16
func GeneratePassword() string {
	mrand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	specials := "*@#$"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	length := 16
	buf := make([]byte, length)
	buf[0] = digits[mrand.Intn(len(digits))]
	buf[1] = specials[mrand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[mrand.Intn(len(all))]
	}
	mrand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	str := string(buf)
	return str
}

func GenerateAndScrambleSecret() {
	EncryptionSecret = GeneratePassword()
	f, err := os.Create(SecretFilepath)
	if err != nil {
		log.Panic.Println("Error while creating secret file in master node: ", err)
		panic(err)
	}
	defer f.Close()
	scrambled_secret := Encode([]byte(getScrambledOrOriginalSecret(EncryptionSecret, true)))
	_, err = f.WriteString(scrambled_secret)
	if err != nil {
		log.Panic.Println("Error while writing secret in the master node : ", err)
		panic(err)
	}
}

func GetEncryptionSecret() string {
	data, err := os.ReadFile(SecretFilepath)
	if err != nil {
		log.Panic.Println("Error reading the secret file")
		panic(err)
	}
	decoded_data, _ := Decode(string(data))
	return getScrambledOrOriginalSecret(string(decoded_data), false)
}

func GetEncryptedConfigStruct(config_struct config.ConfigStruct) (config.ConfigStruct, error) {
	var err error

	config_struct.ClusterDetails.OsCredentials.OsAdminUsername, err = GetEncryptedData(config_struct.ClusterDetails.OsCredentials.OsAdminUsername)
	if err != nil {
		return config_struct, err
	}

	config_struct.ClusterDetails.OsCredentials.OsAdminPassword, err = GetEncryptedData(config_struct.ClusterDetails.OsCredentials.OsAdminPassword)
	if err != nil {
		return config_struct, err
	}

	config_struct.ClusterDetails.CloudCredentials.SecretKey, err = GetEncryptedData(config_struct.ClusterDetails.CloudCredentials.SecretKey)
	if err != nil {
		return config_struct, err
	}

	config_struct.ClusterDetails.CloudCredentials.AccessKey, err = GetEncryptedData(config_struct.ClusterDetails.CloudCredentials.AccessKey)
	if err != nil {
		return config_struct, err
	}

	return config_struct, nil
}

func GetDecryptedConfigStruct(config_struct config.ConfigStruct) config.ConfigStruct {
	os_admin_username := GetDecryptedData(config_struct.ClusterDetails.OsCredentials.OsAdminUsername)
	if os_admin_username != "" {
		config_struct.ClusterDetails.OsCredentials.OsAdminUsername = os_admin_username
	}
	os_admin_password := GetDecryptedData(config_struct.ClusterDetails.OsCredentials.OsAdminPassword)
	if os_admin_password != "" {
		config_struct.ClusterDetails.OsCredentials.OsAdminPassword = os_admin_password
	}

	secret_key := GetDecryptedData(config_struct.ClusterDetails.CloudCredentials.SecretKey)
	if secret_key != "" {
		config_struct.ClusterDetails.CloudCredentials.SecretKey = secret_key
	}
	access_key := GetDecryptedData(config_struct.ClusterDetails.CloudCredentials.AccessKey)
	if access_key != "" {
		config_struct.ClusterDetails.CloudCredentials.AccessKey = access_key
	}
	return config_struct
}

func UpdateEncryptedCred(initialRun bool, config_struct config.ConfigStruct) error {
	encryptedConfigStruct, err := GetEncryptedConfigStruct(config_struct)
	if err != nil {
		log.Panic.Println("Error getting the encrypted config struct : ", err)
		panic(err)
	}

	err = config.UpdateConfigFile(encryptedConfigStruct)
	if err != nil {
		log.Panic.Println("Error updating the encrypted config struct : ", err)
		panic(err)
	}

	// initialize new os client connection with the updated creds
	if !initialRun {
		cfg := config_struct.ClusterDetails
		osutils.InitializeOsClient(cfg.OsCredentials.OsAdminUsername, cfg.OsCredentials.OsAdminPassword)
	}
	return nil
}

func DecryptCredsAndInitializeConn(config_struct config.ConfigStruct) {
	decryptedConfigStruct := GetDecryptedConfigStruct(config_struct)
	cfg := decryptedConfigStruct.ClusterDetails
	osutils.InitializeOsClient(cfg.OsCredentials.OsAdminUsername, cfg.OsCredentials.OsAdminPassword)
}

func UpdateSecretAndEncryptCreds(initial_run bool, config_struct config.ConfigStruct) error {
	if initial_run {
		if _, err := os.Stat(SecretFilepath); err == nil {
			EncryptionSecret = GetEncryptionSecret()
		} else if errors.Is(err, os.ErrNotExist) {
			if utils.CheckIfMaster(context.Background(), "") {
				GenerateAndScrambleSecret()
				UpdateEncryptedCred(initial_run, config_struct)
				//ansible logic to copy the secret and config
			} else {
				log.Info.Println("Sleeping for 20 sec for the secrets to be updated from the master node")
				// contiuous loop to check if the config and secret is present in the nodes initially
				for {
					time.Sleep(20 * time.Second)
					if _, err := os.Stat(SecretFilepath); err == nil {
						EncryptionSecret = GetEncryptionSecret()
						break
					} else if errors.Is(err, os.ErrNotExist) {
						log.Warn.Println("Secret file not yet created")
					} else {
						log.Panic.Println("Error in reading secret file : ", err)
						panic(err)
					}
				}
			}
		} else {
			log.Panic.Println("Error in reading secret file : ", err)
			panic(err)
		}
	} else {
		if utils.CheckIfMaster(context.Background(), "") {
			decrypted_struct := GetDecryptedConfigStruct(config_struct)
			GenerateAndScrambleSecret()
			UpdateEncryptedCred(initial_run, decrypted_struct)
			//ansible logic to copy the secret and config
		} else {
			EncryptionSecret = GetEncryptionSecret()
			DecryptCredsAndInitializeConn(config_struct)

		}
	}

	return nil
}

func CredsMismatch(currentConfigStruct config.ConfigStruct, previousConfigStruct config.ConfigStruct) bool {
	if (currentConfigStruct.ClusterDetails.OsCredentials.OsAdminUsername != previousConfigStruct.ClusterDetails.OsCredentials.OsAdminUsername) ||
		(currentConfigStruct.ClusterDetails.OsCredentials.OsAdminPassword != previousConfigStruct.ClusterDetails.OsCredentials.OsAdminPassword) ||
		(currentConfigStruct.ClusterDetails.CloudCredentials.SecretKey != previousConfigStruct.ClusterDetails.CloudCredentials.SecretKey) ||
		(currentConfigStruct.ClusterDetails.CloudCredentials.AccessKey != previousConfigStruct.ClusterDetails.CloudCredentials.AccessKey) {
		return true
	}
	return false
}

// Encode the given byte value
func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, EncryptionSecret string) (string, error) {
	block, err := aes.NewCipher([]byte(EncryptionSecret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encode(cipherText), nil
}

// Decode the given string
func Decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if !strings.Contains(err.Error(), "illegal base64 data at input") {
			log.Panic.Println("Error while decoding : ", err)
			panic(err)
		} else {
			return data, err
		}
	}
	return data, nil
}

// Decrypt method is to extract back the encrypted text
func Decrypt(text, EncryptionSecret string) (string, error) {
	block, err := aes.NewCipher([]byte(EncryptionSecret))
	if err != nil {
		log.Error.Println("Error while creating cipher during decryption : ", err)
		return "", err
	}
	cipherText, err := Decode(text)
	if err != nil {
		return "", nil
	}
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

// Creates an encrypted string : performs AES encryption using the defined secret
// and return base64 encoded string. Also checks if the encrypted string is able
// to be decrypted used the same secret.
func GetEncryptedData(toBeEncrypted string) (string, error) {
	encText, err := Encrypt(toBeEncrypted, EncryptionSecret)
	if err != nil {
		return "", err
	} else {
		_, err := Decrypt(encText, EncryptionSecret)
		if err != nil {
			log.Error.Println("Error decrypting your encrypted text: ", err)
			return "", err
		}
	}
	return encText, nil
}

// Return the decrypted string of the given encrypted string
func GetDecryptedData(encryptedString string) string {
	decrypted_txt, err := Decrypt(encryptedString, EncryptionSecret)
	if err != nil {
		log.Panic.Println("Error decrypting your encrypted text: ", err)
		panic(err)
	}
	return decrypted_txt
}

// Converts a 16 len string to 4*4 matrix
func stringToMatrix(str string) [4][4]string {
	var matrix [4][4]string
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			matrix[i][j] = string(str[i*4+j])
		}
	}
	return matrix
}

// Returns the transpose of the given matrix
func transpose(matrix [4][4]string) [4][4]string {
	var transposedMatrix [4][4]string
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			transposedMatrix[j][i] = matrix[i][j]
		}
	}
	return transposedMatrix
}

// Returns the matrix with interchanged rows
func reverse(matrix [4][4]string) [4][4]string {
	for i, j := 0, len(matrix)-1; i < j; i, j = i+1, j-1 {
		matrix[i], matrix[j] = matrix[j], matrix[i]
	}
	return matrix
}

// Returns the matrix with intergchanged diagonal values
func reverse_diag(matrix [4][4]string) [4][4]string {
	for i := 0; i < 4; i++ {
		temp := matrix[i][i]
		matrix[i][i] = matrix[i][4-i-1]
		matrix[i][4-i-1] = temp
	}
	return matrix
}

// Input :
// secret (string) : The string which needs to be scrambled or unscrambled
// scrambled (boolean) : True for scramble, false for unscramble
//
// Description :
// This function scrambles and unscrambles the given string by converting it
// into matrix and interchanging the values in it.
//
// Output :
// string : scrambled or unscrambled string as per the requirement
func getScrambledOrOriginalSecret(secret string, scrambled bool) string {
	var requiredArr []string
	matrix := stringToMatrix(secret)
	if scrambled {
		matrix = reverse_diag(reverse(transpose(matrix)))
	} else {
		matrix = transpose(reverse(reverse_diag(matrix)))
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			requiredArr = append(requiredArr, matrix[i][j])
		}
	}
	return strings.Join(requiredArr, "")
}
