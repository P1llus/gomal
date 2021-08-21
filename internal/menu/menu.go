package menu

import (
	"fmt"
	"os"

	"github.com/P1llus/gomal/internal/injection"
	"github.com/manifoldco/promptui"
)

func CreateWelcomeMenu() {
	fmt.Println("Welcome kiddo, please choose your poison!")
	prompt := promptui.Select{
		Label: "Select category",
		Items: []string{"Injections"},
	}

	_, res, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	if res == "Injections" {
		createInjectionMenu()
	} else {
		fmt.Println("No menu choice found, exiting")
	}
	os.Exit(0)
}

func createInjectionMenu() {
	prompt := promptui.Select{
		Label: "Select type of injection",
		Items: []string{"CreateRemoteThread", "CreateFiberThread", "CreateProcessWithPipe", "QueueUserApc"},
	}

	_, res, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	if res == "CreateRemoteThread" {
		injection.CreateRemoteThread()
	} else if res == "CreateFiberThread" {
		injection.CreateFiberThread()
	} else if res == "CreateProcessWithPipe" {
		injection.CreateProcessWithPipe()
	} else if res == "QueueUserApc" {
		injection.QueueUserAPC()
		return
	}
}
