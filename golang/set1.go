package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"sort"
	"strings"
)

func main() {
	//TestHexToBase64()
	//TestFixedXor()
	//TestSingleByteXorCipher()
	//TestDetectSingleCharacterXor()
	//TestRepeatingKeyXor()
	//TestBreakRepeatingKeyXor()
	TestAesEncrypt()
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
			oneByte = (hi - '0') << 4
		} else if hi >= 'a' && hi <= 'f' {
			oneByte = (hi - 'a' + 10) << 4
		} else if hi >= 'A' && hi <= 'F' {
			oneByte = (hi - 'A' + 10) << 4
		} else {
			return "", errors.New("invalid hex string")
		}
		lo := hex[i+1]
		if lo >= '0' && lo <= '9' {
			oneByte |= lo - '0'
		} else if lo >= 'a' && lo <= 'f' {
			oneByte |= lo - 'a' + 10
		} else if lo >= 'A' && lo <= 'F' {
			oneByte |= lo - 'A' + 10
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
	hexInput := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	answer := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	println("======== Testing Challenge 1: Hex to Base64 ========")
	b64, _ := HexToBase64(hexInput)
	println("answer: ", answer)
	println("yours : ", b64)
	if b64 != answer {
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
			oneByte = (hi - '0') << 4
		} else if hi >= 'a' && hi <= 'f' {
			oneByte = (hi - 'a' + 10) << 4
		} else if hi >= 'A' && hi <= 'F' {
			oneByte = (hi - 'A' + 10) << 4
		} else {
			return make([]byte, 0), errors.New("invalid hex string")
		}
		lo := hex[i+1]
		if lo >= '0' && lo <= '9' {
			oneByte |= lo - '0'
		} else if lo >= 'a' && lo <= 'f' {
			oneByte |= lo - 'a' + 10
		} else if lo >= 'A' && lo <= 'F' {
			oneByte |= lo - 'A' + 10
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

func EvaluateWordScore(msg []byte) float64 {
	scores := map[byte]float64{
		'a': 8.167,
		'b': 1.492,
		'c': 2.782,
		'd': 4.253,
		'e': 12.702,
		'f': 2.228,
		'g': 2.015,
		'h': 6.094,
		'i': 6.966,
		'j': 0.153,
		'k': 0.772,
		'l': 4.025,
		'm': 2.406,
		'n': 6.749,
		'o': 7.507,
		'p': 1.929,
		'q': 0.095,
		'r': 5.987,
		's': 6.327,
		't': 9.056,
		'u': 2.758,
		'v': 0.978,
		'w': 2.360,
		'x': 0.150,
		'y': 1.974,
		'z': 0.074,
	}
	result := 0.0
	for _, r := range msg {
		if score, ok := scores[r]; ok {
			result += score
		}
	}
	result /= float64(len(msg))
	return result
}

func SingleByteXor(msg []byte, key byte) []byte {
	result := make([]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		result[i] = msg[i] ^ key
	}
	return result
}

func BreakSingleByteXor(cipherBytes []byte) (byte, float64, error) {
	highestScore := 0.0
	var answer *[]byte
	var k byte
	for i := 0; i < 256; i++ {
		plainBytes := SingleByteXor(cipherBytes, byte(i))
		abnormal := false
		for _, c := range plainBytes {
			if c < '\n' || c > '~' {
				abnormal = true
				break
			}
		}
		if abnormal {
			continue
		}
		score := EvaluateWordScore(plainBytes)
		if score > highestScore {
			highestScore = score
			answer = &plainBytes
			k = byte(i)
		}
	}
	if answer == nil {
		return 0, 0.0, nil
	}
	return k, highestScore, nil
}

func SingleByteXorCipher(cipherBytes []byte) ([]byte, float64, byte, error) {
	highestScore := 0.0
	var answer *[]byte
	var k byte
	for i := 0; i < 256; i++ {
		plainBytes := SingleByteXor(cipherBytes, byte(i))
		abnormal := false
		for _, c := range plainBytes {
			if c < '\n' || c > '~' {
				abnormal = true
				break
			}
		}
		if abnormal {
			continue
		}
		score := EvaluateWordScore(plainBytes)
		if score > highestScore {
			highestScore = score
			answer = &plainBytes
			k = byte(i)
		}
	}
	if answer == nil {
		return make([]byte, 0), 0.0, 0, nil
	}
	return *answer, highestScore, k, nil
}

func TestSingleByteXorCipher() {
	println("======== Testing Challenge 3: Single-byte XOR cipher ========")
	cipher := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherBytes, _ := HexToBytes(cipher)
	msg, _, _, err := SingleByteXorCipher(cipherBytes)
	if err != nil {
		println("Oops. Failed.")
	} else {
		println("answer:", "Cooking MC's like a pound of bacon")
		println("yours :", string(msg))
		if string(msg) != "Cooking MC's like a pound of bacon" {
			println("Oops. Failed.")
		} else {
			println("Congratulations! Passed.")
		}
	}
}

// Challenge 4: Detect single-character XOR

func DetectSingleCharacterXor() ([]byte, error) {
	filename := "4.txt"
	file, err := os.Open(filename)
	if err != nil {
		return make([]byte, 0), err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	scanner := bufio.NewScanner(file)
	var answer *[]byte
	highestScore := 0.0
	for scanner.Scan() {
		line := scanner.Text()
		cipherBytes, _ := HexToBytes(line)
		result, score, _, err := SingleByteXorCipher(cipherBytes)
		if err != nil {
			return make([]byte, 0), err
		}
		if score > highestScore {
			highestScore = score
			answer = &result
		}
	}
	if err := scanner.Err(); err != nil {
		return make([]byte, 0), err
	}
	return *answer, nil
}

func TestDetectSingleCharacterXor() {
	println("======== Testing Challenge 4: Detect single-character XOR ========")
	ans, err := DetectSingleCharacterXor()
	if err != nil {
		fmt.Printf("Oops. Failed. %v\n", err)
	} else {
		println("answer:", "Now that the party is jumping\n")
		println("yours :", string(ans))
		if string(ans) != "Now that the party is jumping\n" {
			println("Oops. Failed.")
		} else {
			println("Congratulations! Passed.")
		}
	}
}

// Challenge 5: Implement repeating-key XOR

func RepeatingKeyXor(msg []byte, key []byte) ([]byte, error) {
	result := make([]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		result[i] = msg[i] ^ key[i%len(key)]
	}
	return result, nil
}

func TestRepeatingKeyXor() {
	println("======== Testing Challenge 5: Implement repeating-key XOR ========")
	msg := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	answer := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	result, err := RepeatingKeyXor([]byte(msg), []byte(key))
	if err != nil {
		fmt.Printf("Oops. Failed, %v", err)
	} else {
		println("answer:", answer)
		println("yours :", hex.EncodeToString(result))
		if hex.EncodeToString(result) != answer {
			println("Oops. Failed.")
		} else {
			println("Congratulations! Passed.")
		}
	}
}

// Challenge 6: Break repeating-key XOR

func HammingDistanceOf(a, b []byte) int {
	if len(a) > len(b) {
		a, b = b, a
	}
	var result int
	for i := 0; i < len(a); i++ {
		result += bits.OnesCount(uint(a[i] ^ b[i]))
	}
	return result
}

func DetectNKeySize(cipherBytes []byte, n int) []int {

	keySizes := make(map[float64]int, 39)
	distances := make([]float64, 39)
	for keySize := 2; keySize <= 40; keySize++ {
		// TODO: allow for not aligned keySize
		if keySize*4 > len(cipherBytes) {
			break
		}
		distance := 0.0
		nblocks := len(cipherBytes) / keySize
		for i := 0; i < nblocks-1; i++ {
			distance += float64(HammingDistanceOf(cipherBytes[keySize*i:keySize*(i+1)], cipherBytes[keySize*(i+1):keySize*(i+2)]))
		}
		distance /= float64(nblocks)
		distance /= float64(keySize)
		keySizes[distance] = keySize
		distances[keySize-2] = distance
	}
	sort.Float64s(distances)
	result := make([]int, n)
	for i, dis := range distances[0:n] {
		result[i] = keySizes[dis]
	}
	return result
}

func TransposeBlocks(cipherBytes []byte, keySize int) [][]byte {
	blockSize := len(cipherBytes) / keySize
	blocks := make([][]byte, keySize)
	for ks := 0; ks < keySize; ks++ {
		blocks[ks] = make([]byte, blockSize)
		for bs := 0; bs < blockSize; bs++ {
			blocks[ks][bs] = cipherBytes[keySize*bs+ks]
		}
	}
	return blocks
}

func BreakRepeatingKeyXor(cipher []byte) ([]byte, []byte, error) {
	//keySize, err := DetectKeySize(cipher)
	keySizes := DetectNKeySize(cipher, 1)
	var key []byte
	highestScore := 0.0
	for _, keySize := range keySizes {
		result := make([]byte, keySize)
		blocks := TransposeBlocks(cipher, keySize)
		kScore := 0.0
		for i := 0; i < keySize; i++ {
			k, score, err := BreakSingleByteXor(blocks[i])
			if err != nil {
				return nil, nil, err
			}
			result[i] = k
			kScore += score
		}
		kScore /= float64(keySize)
		if kScore > highestScore {
			highestScore = kScore
			key = result
		}
	}
	msg, err := RepeatingKeyXor(cipher, key)
	return msg, key, err
}

func TestBreakRepeatingKeyXor() {
	fmt.Println("======== Testing Challenge 6: Break repeating-key XOR ========")
	hammingAnswer := 37
	yoursHamming := HammingDistanceOf([]byte("this is a test"), []byte("wokka wokka!!!"))
	if yoursHamming != hammingAnswer {
		fmt.Printf("Oops. Failed. Hamming distance is %d, not %d.\n", yoursHamming, hammingAnswer)
		os.Exit(1)
	} else {
		fmt.Println("Hamming distance is correct.")
	}
	file, err := os.Open("6.txt")
	if err != nil {
		fmt.Printf("Failed to open file!")
		os.Exit(1)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Failed to close file!")
			os.Exit(1)
		}
	}(file)
	scanner := bufio.NewScanner(file)
	lines := make([]string, 512)
	idx := 0
	for scanner.Scan() {
		line := scanner.Text()
		lines[idx] = line
		idx += 1
	}
	b64Content := strings.Join(lines, "")
	cipher, err := base64.StdEncoding.DecodeString(b64Content)
	if err != nil {
		fmt.Printf("Fail to parse file!")
		os.Exit(1)
	}
	_, key, err := BreakRepeatingKeyXor(cipher)
	keyAnswer := "Terminator X: Bring the noise"
	fmt.Println("key   :", keyAnswer)
	fmt.Println("yours :", string(key))
	if string(key) != keyAnswer {
		fmt.Println("Oops. Failed. Key is incorrect.")
		os.Exit(1)
	} else {
		fmt.Println("Key is correct.")
	}
	answer, err := os.ReadFile("6_answer.bin")
	if err != nil {
		fmt.Printf("Oops. Failed, %v", err)
	} else {
		fmt.Println("answer:", string(answer)[:32], "...")
	}
	result, err := RepeatingKeyXor(cipher, key)
	if err != nil {
		fmt.Printf("Oops. Failed, %v", err)
	} else {
		fmt.Println("yours :", string(result)[:32], "...")
	}
	cmpRes := bytes.Compare(result, answer)
	if cmpRes == 0 {
		fmt.Println("Congratulations! Passed.")
	} else {
		fmt.Println("Oops. Failed.")
	}
}

// Challenge 7: AES in ECB mode

type CipherBlock interface {
	BlockSize() int
	EncryptEcb(dst []byte, src []byte)
	DecryptEcb(dst []byte, src []byte)
}

const AesBlockSize = 16

func NewAesCipher(k []byte) (CipherBlock, error) {
	return nil, nil
}

func AesEncrypt() {

}

func AesDecrypt() {

}

func TestAesEncrypt() {
	aesCipherBlock, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		fmt.Printf("Oops. Failed. %v\n", err)
		os.Exit(1)
	}
	file, err := os.Open("golang/7.txt")
	if err != nil {
		fmt.Printf("Failed to open file!")
		os.Exit(1)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("Failed to close file!")
			os.Exit(1)
		}
	}(file)
	scanner := bufio.NewScanner(file)
	lines := make([]string, 512)
	idx := 0
	for scanner.Scan() {
		line := scanner.Text()
		lines[idx] = line
		idx += 1
	}
	b64Content := strings.Join(lines, "")
	cipher, err := base64.StdEncoding.DecodeString(b64Content)
	if err != nil {
		fmt.Printf("Fail to parse file!")
		os.Exit(1)
	}
	message := make([]byte, 32768)
	for i := 0; i < len(cipher); i += 16 {
		aesCipherBlock.Decrypt(message[i:], cipher[i:])
	}
	fmt.Println(string(message))
}
