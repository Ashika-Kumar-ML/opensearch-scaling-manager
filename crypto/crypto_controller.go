package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	mrand "math/rand"
	"os"
	"scaling_manager/logger"
	utils "scaling_manager/utilities"
	"strings"
	"time"
)

var log = new(logger.LOG)
var EncryptionSecret string
var seed = time.Now().Unix()

// Initializing logger module
func init() {
	log.Init("logger")
	log.Info.Println("Crypto module initiated")
	mrand.Seed(seed)
	err := CheckAndUpdateSecretFile("secret.txt", false)
	if err != nil {
		panic(err)
	}

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

func GenerateAndScrambleSecret(filepath string) {
	EncryptionSecret = GeneratePassword()
	f, err := os.Create(filepath)
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

// Input :
// secret_filepath (string) : path for the secret file
// file_handler (bool) : True, if this function is called from the file event handler,
// False, otherwise
//
// Description :
// This function returns the secret if present, else creates a secret file with scrambled
// secret. This function will be called twice (at the beginning of the execution and when
// there is any updates in the config file). When called at the beginning, the secret will
// be generated only in the master node. The encrypted config file along with the scrambled
// secret file will be sent to the other nodes. When called from the file event handler,
// the secret will be generated in the node which invokes this event, and sends the secret
// and config file to other nodes.
//
// Output :
// Error (if any)
func CheckAndUpdateSecretFile(secret_filepath string, file_handler bool) error {
	if !file_handler {
		if _, err := os.Stat(secret_filepath); err == nil {
			data, err := os.ReadFile(secret_filepath)
			if err != nil {
				log.Panic.Println("Error reading the secret file")
				return err
			}
			decoded_data, _ := Decode(string(data))
			EncryptionSecret = getScrambledOrOriginalSecret(string(decoded_data), false)
		} else if errors.Is(err, os.ErrNotExist) {
			if utils.CheckIfMaster(context.Background(), "") {
				GenerateAndScrambleSecret(secret_filepath)
				// Integrate ansible script to send the secret and config to other nodes
			} else {
				log.Info.Println("Sleeping for 20 sec for the secrets to be updated from the master node")
				// contiuous loop to check if the secret is present in the nodes initially
				for {
					time.Sleep(20 * time.Second)
					if _, err := os.Stat(secret_filepath); err == nil {
						data, err := os.ReadFile(secret_filepath)
						if err != nil {
							log.Panic.Println("Error reading the secret file")
							return err
						}
						decoded_data, _ := Decode(string(data))
						EncryptionSecret = getScrambledOrOriginalSecret(string(decoded_data), false)
						break
					} else if errors.Is(err, os.ErrNotExist) {
						log.Warn.Println("Secret file not yet created")
					} else {
						log.Panic.Println("Error in reading secret file")
						panic(err)
					}
				}
			}
		} else {
			log.Panic.Println("Error in reading secret file")
			panic(err)
		}
	} else {
		GenerateAndScrambleSecret(secret_filepath)
		// Integrate ansible script to send the secret and config to other nodes
	}
	return nil
}

// Encode the given byte value
func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Encrypt method is to encrypt or hide any classified text
func Encrypt(text, EncryptionSecret string) (string, error) {
	block, err := aes.NewCipher([]byte(EncryptionSecret))
	if err != nil {
		log.Error.Println("Error while creating cipher during encryption : ", err)
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
			return nil, err
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
		log.Error.Println("Error encrypting your classified text: ", err)
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
