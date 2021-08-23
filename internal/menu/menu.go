package menu

import (
	"fmt"
	"os"

	"github.com/P1llus/gomal/internal/injection"
	"github.com/P1llus/gomal/internal/ransomware"
	"github.com/manifoldco/promptui"
)

func CreateWelcomeMenu() {
	fmt.Println("Welcome kiddo, please pick your poison!")
	prompt := promptui.Select{
		Label: "Select category",
		Items: []string{"Injections", "Ransomware"},
	}

	_, res, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	if res == "Injections" {
		createInjectionMenu()
	} else if res == "Ransomware" {
		createRansomwareMenu()
	} else if res == "Exit" {
		os.Exit(1)
	}
	CreateWelcomeMenu()
}

func createInjectionMenu() {
	prompt := promptui.Select{
		Label: "Select type of injection",
		Items: []string{"CreateRemoteThread", "CreateThread", "CreateFiberThread", "CreateProcess", "CreateProcessWithPipe", "QueueUserApc (Early Bird)", "NtQueueApcThreadEx", "CreateEtwThread", "RtlCreateUserThread", "Syscall", "UUIDFromString"},
		Size:  15,
	}

	_, res, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	if res == "CreateRemoteThread" {
		injection.CreateRemoteThreads()
	} else if res == "CreateThreads" {
		injection.CreateThread()
	} else if res == "CreateFiberThread" {
		injection.CreateFiberThread()
	} else if res == "CreateProcess" {
		injection.CreateProcess()
	} else if res == "CreateProcessWithPipe" {
		injection.CreateProcessWithPipe()
	} else if res == "QueueUserApc (Early Bird)" {
		injection.EarlyBird()
	} else if res == "NtQueueApcThreadEx" {
		injection.NtQueueApcThread()
	} else if res == "CreateEtwThread" {
		injection.CreateEtwThread()
	} else if res == "RtlCreateUserThread" {
		injection.RtlCreateUserThreads()
	} else if res == "Syscall" {
		injection.Syscall()
	} else if res == "UUIDFromString" {
		injection.UUIDFromString()
	}
}

func createRansomwareMenu() {
	prompt := promptui.Select{
		Label: "What action do you want to perform",
		Items: []string{"Encrypt Folder", "Decrypt Folder"},
		Size:  15,
	}

	_, res, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	if res == "Encrypt Folder" {
		res := createRansomwarePathMenu()
		if res == "" {
			return
		}
		ransomware.Run("encrypt", res)
	}
	if res == "Decrypt Folder" {
		res := createRansomwarePathMenu()
		if res == "" {
			return
		}
		ransomware.Run("decrypt", res)
	}
}

func createRansomwarePathMenu() string {
	prompt := promptui.Prompt{
		Label: "Please provide full path to folder or file",
	}

	result, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return ""
	}
	if _, err := os.Stat(result); os.IsNotExist(err) {
		fmt.Println("File or folder not found")
		return ""
	}
	fmt.Printf("You choose %q\n", result)
	return result
}
