package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

func main() {
	TestHexToBase64()
	TestFixedXor()
	TestSingleByteXorCipher()
	TestDetectSingleCharacterXor()
	TestRepeatingKeyXor()
}

// Challenge 1: Hex to Base64

func HexToBase64(hex string) (string, error) {
	if len(hex)%2 != 0 {
		return "", errors.New("invalid hex string")
	}

	length := len(hex) / 2
	buf := make([]byte, length)
	var oneByte uint8 = 0
	for i := 0; i < len(hex); i += 2 {
		hi := hex[i]
		if hi >= '0' && hi <= '9' {
			oneByte = uint8(hi-'0') << 4
		} else if hi >= 'a' && hi <= 'f' {
			oneByte = uint8(hi-'a'+10) << 4
		} else if hi >= 'A' && hi <= 'F' {
			oneByte = uint8(hi-'A'+10) << 4
		} else {
			return "", errors.New("invalid hex string")
		}
		lo := hex[i+1]
		if lo >= '0' && lo <= '9' {
			oneByte |= uint8(lo - '0')
		} else if lo >= 'a' && lo <= 'f' {
			oneByte |= uint8(lo - 'a' + 10)
		} else if lo >= 'A' && lo <= 'F' {
			oneByte |= uint8(lo - 'A' + 10)
		} else {
			return "", errors.New("invalid hex string")
		}
		buf[i/2] = oneByte
	}
	base64Codec := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, length*4/3)
	for i := 0; i < length/3; i += 1 {
		bufIndex := i * 3
		resultIndex := i * 4
		result[resultIndex] = base64Codec[buf[bufIndex]>>2]
		result[resultIndex+1] = base64Codec[(buf[bufIndex]&0x03)<<4|buf[bufIndex+1]>>4]
		result[resultIndex+2] = base64Codec[(buf[bufIndex+1]&0x0f)<<2|buf[bufIndex+2]>>6]
		result[resultIndex+3] = base64Codec[buf[bufIndex+2]&0x3f]
	}
	// Last chunk
	if length%3 == 1 {
		result = append(result, base64Codec[buf[length-1]>>2], base64Codec[(buf[length-1]&0x03)<<4])
		result = append(result, '=', '=')
	} else if length%3 == 2 {
		result = append(result, base64Codec[buf[length-2]>>2], base64Codec[(buf[length-2]&0x03)<<4|buf[length-1]>>4], base64Codec[(buf[length-1]&0x0f)<<2])
		result = append(result, '=')
	}
	return string(result), nil
}

func TestHexToBase64() {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	answer := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	println("======== Testing Challenge 1: Hex to Base64 ========")
	base64, _ := HexToBase64(hex)
	println("answer: ", answer)
	println("yours : ", base64)
	if base64 != answer {
		println("Oops. Failed.")
	} else {
		println("Congratulations! Passed.")
	}
}

// Challenge 2: Fixed XOR

func HexToBytes(hex string) ([]byte, error) {
	length := len(hex) / 2
	buf := make([]byte, length)
	var oneByte uint8 = 0
	for i := 0; i < len(hex); i += 2 {
		hi := hex[i]
		if hi >= '0' && hi <= '9' {
			oneByte = uint8(hi-'0') << 4
		} else if hi >= 'a' && hi <= 'f' {
			oneByte = uint8(hi-'a'+10) << 4
		} else if hi >= 'A' && hi <= 'F' {
			oneByte = uint8(hi-'A'+10) << 4
		} else {
			return make([]byte, 0), errors.New("invalid hex string")
		}
		lo := hex[i+1]
		if lo >= '0' && lo <= '9' {
			oneByte |= uint8(lo - '0')
		} else if lo >= 'a' && lo <= 'f' {
			oneByte |= uint8(lo - 'a' + 10)
		} else if lo >= 'A' && lo <= 'F' {
			oneByte |= uint8(lo - 'A' + 10)
		} else {
			return make([]byte, 0), errors.New("invalid hex string")
		}
		buf[i/2] = oneByte
	}
	return buf, nil
}

func FixedXor(msgHex string, passHex string) (string, error) {
	msg, err := HexToBytes(msgHex)
	if err != nil {
		return "", err
	}
	pass, err := HexToBytes(passHex)
	if err != nil {
		return "", err
	}
	if len(msg) != len(pass) {
		return "", errors.New("msg and pass must be the same length")
	}
	result := make([]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		result[i] = msg[i] ^ pass[i]
	}
	return hex.EncodeToString(result), nil
}

func TestFixedXor() {
	msgHex := "1c0111001f010100061a024b53535009181c"
	passHex := "686974207468652062756c6c277320657965"
	answer := "746865206b696420646f6e277420706c6179"
	println("======== Testing Challenge 2: Fixed XOR ========")
	result, _ := FixedXor(msgHex, passHex)
	println("answer: ", answer)
	println("yours : ", result)
	if result != answer {
		println("Oops. Failed.")
	} else {
		println("Congratulations! Passed.")
	}

}

// Challenge 3: Single-byte XOR cipher

func SingbleByteXor(msg []byte, key byte) []byte {
	result := make([]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		result[i] = msg[i] ^ key
	}
	return result
}

func SingleByteXorCipher(cipher string) (string, error) {
	cipherBytes, err := HexToBytes(cipher)
	if err != nil {
		return "", err
	}
	alphaCounter := 0
	answer := make([]byte, len(cipherBytes))
	for i := 0; i < 256; i++ {
		plainBytes := SingbleByteXor(cipherBytes, byte(i))
		plain := string(plainBytes)
		tmpCounter := 0
		for _, c := range plain {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				tmpCounter++
			}
		}
		if tmpCounter > alphaCounter {
			alphaCounter = tmpCounter
			copy(answer, plainBytes)
		}
	}
	return string(answer), nil
}

func TestSingleByteXorCipher() {
	println("======== Testing Challenge 3: Single-byte XOR cipher ========")
	cipher := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	msg, err := SingleByteXorCipher(cipher)
	if err != nil {
		println("Oops. Failed.")
	} else {
		println("answer:", "Cooking MC's like a pound of bacon")
		println("yours :", msg)
		if msg != "Cooking MC's like a pound of bacon" {
			println("Oops. Failed.")
		} else {
			println("Congratulations! Passed.")
		}
	}
}

// Challenge 4: Detect single-character XOR
func DetectSingleCharacterXor() (string, error) {
	filename := "4.txt"
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var answer string
	alphaCounter := 0
	for scanner.Scan() {
		line := scanner.Text()
		result, err := SingleByteXorCipher(line)
		if err != nil {
			return "", err
		}
		tmpCounter := 0
		for _, c := range result {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				tmpCounter++
			}
		}
		if tmpCounter > alphaCounter {
			answer = result
			alphaCounter = tmpCounter
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return answer, nil
}

func TestDetectSingleCharacterXor() {
	println("======== Testing Challenge 4: Detect single-character XOR ========")
	ans, err := DetectSingleCharacterXor()
	if err != nil {
		println("Oops. Failed.")
	} else {
		println("answer:", "Now that the party is jumping\n")
		println("yours :", ans)
		if ans != "Now that the party is jumping\n" {
			println("Oops. Failed.")
		} else {
			println("Congratulations! Passed.")
		}
	}
}

// Challenge 5: Implement repeating-key XOR
func RepeatingKeyXor(msg string, key string) (string, error) {
	msgBytes := []byte(msg)
	keyBytes := []byte(key)
	result := make([]byte, len(msgBytes))
	for i := 0; i < len(msgBytes); i++ {
		result[i] = msgBytes[i] ^ keyBytes[i%len(keyBytes)]
	}
	return hex.EncodeToString(result), nil
}

func TestRepeatingKeyXor() {
	println("======== Testing Challenge 5: Implement repeating-key XOR ========")
	msg := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	answer := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	result, err := RepeatingKeyXor(msg, key)
	if err != nil {
		fmt.Printf("Oops. Failed, %v", err)
	} else {
		println("answer:", answer)
		println("yours :", result)
		if result != answer {
			println("Oops. Failed.")
		} else {
			println("Congratulations! Passed.")
		}
	}
}
