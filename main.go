package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inancgumus/screen"
)

const (
	letters        = "abcdefghijklmnopqrstuvwxyz"
	passwordLength = 5
)

func main() {
	for {
		screen.Clear()
		screen.MoveTopLeft()

		hashesToFind := getHashesFromUser()
		if len(hashesToFind) == 0 {
			fmt.Println("Нет хэшей!")
			continue
		}

		screen.Clear()
		screen.MoveTopLeft()

		var choice int
		fmt.Println("Выберите способ взлома:")
		fmt.Println("1. В однопоточном режиме")
		fmt.Println("2. В многопоточном режиме")
		fmt.Scan(&choice)
		clearStdin()

		screen.Clear()
		screen.MoveTopLeft()

		switch choice {
		case 1:
			fmt.Println("Запуск в однопоточном режиме...")
			bruteForceSingleThread(hashesToFind)
		case 2:
			fmt.Println("Введите количество потоков:")
			var numWorkers int
			fmt.Scan(&numWorkers)
			clearStdin()
			if numWorkers == 0 {
				numWorkers = runtime.NumCPU()
			}

			fmt.Println("Запуск в многопоточном режиме...")
			bruteForceMultiThread(hashesToFind, numWorkers)
		}

		pause()
	}
}

func getHashesFromUser() []string {
	var choice int
	fmt.Println("Выберите источник хэшей:")
	fmt.Println("1. Ввод с консоли")
	fmt.Println("2. Чтение из файла")
	fmt.Println("3. Использовать предопределённые значения")

	fmt.Scan(&choice)
	clearStdin()

	screen.Clear()
	screen.MoveTopLeft()

	switch choice {
	case 1:
		var hashes []string
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("Введите хэши (вводите по одному, закончите ввод пустой строкой):")
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text == "" {
				break
			}
			hashes = append(hashes, text)
		}
		return hashes
	case 2:
		var fileName string
		fmt.Print("Введите имя файла: ")
		fmt.Scan(&fileName)

		hashes, err := readHashesFromFile(fileName)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return nil
		}
		return hashes
	default:
		return []string{
			"1115dd800feaacefdf481f1f9070374a2a81e27880f187396db67958b207cbad",
			"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
			"74e1bb62f8dabb8125a58852b63bdf6eaef667cb56ac7f7cdba6d7305c50a22f",
			"7a68f09bd992671bb3b19a5e70b7827e",
		}
	}
}

func readHashesFromFile(fileName string) ([]string, error) {
	path := filepath.Join("hash", fileName)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hashes = append(hashes, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hashes, nil
}

func md5Hash(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func generatePassword(index int) string {
	var password [passwordLength]byte
	for i := 0; i < passwordLength; i++ {
		password[i] = letters[index%len(letters)]
		index /= len(letters)
	}
	return string(password[:])
}

func bruteForceSingleThread(hashes []string) {
	start := time.Now()

	var (
		isFind  = make([]bool, len(hashes))
		lenFind int
	)

	totalCombinations := len(letters) * len(letters) * len(letters) * len(letters) * len(letters)

	for count := 0; count < totalCombinations; count++ {
		passStr := generatePassword(count)
		md5HashVal := md5Hash(passStr)
		sha256HashVal := sha256Hash(passStr)

		for i, hashVal := range hashes {
			if hashVal == md5HashVal || hashVal == sha256HashVal {
				isFind[i] = true
				lenFind++
				fmt.Printf("Пароль найден для %s: %s\n", hashVal, passStr)
			}
		}
	}

	fmt.Printf("Однопоточный режим завершен за %s\n\n", time.Since(start))

	if len(hashes)-lenFind != 0 {
		fmt.Println("Не удалось расшифровать следующие хэши:")
		for i, hashVal := range isFind {
			if !hashVal {
				fmt.Println(hashes[i])
			}
		}
	}

}

func bruteForceMultiThread(hashes []string, workers int) {
	start := time.Now()

	var (
		isFind  = make([]bool, len(hashes))
		lenFind atomic.Int32
	)

	var wg sync.WaitGroup
	totalCombinations := len(letters) * len(letters) * len(letters) * len(letters) * len(letters)

	chunkSize := totalCombinations / workers
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			startIndex := worker * chunkSize
			endIndex := startIndex + chunkSize
			if worker == workers-1 {
				endIndex = totalCombinations
			}

			for count := startIndex; count < endIndex; count++ {
				passStr := generatePassword(count)
				md5HashVal := md5Hash(passStr)
				sha256HashVal := sha256Hash(passStr)

				for i, hashVal := range hashes {
					if hashVal == md5HashVal || hashVal == sha256HashVal {
						lenFind.Add(1)
						isFind[i] = true
						fmt.Printf("Пароль найден для %s: %s\n", hashVal, passStr)
					}
				}
			}
		}(worker)
	}

	wg.Wait()
	fmt.Printf("Многопоточный режим завершен за %s\n", time.Since(start))

	if int32(len(hashes))-lenFind.Load() != 1 {
		fmt.Println("Не удалось расшифровать следующие хэши:", passwordLength-lenFind.Load())
		for i, hashVal := range isFind {
			if !hashVal {
				fmt.Println(hashes[i])
			}
		}
	}
}

func clearStdin() {
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func pause() {
	fmt.Print("Нажмите Enter для продолжения...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	// bufio.NewReader(os.Stdin).ReadBytes('\n')
}
