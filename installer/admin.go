package main

func getPrivilegeLevel() string {
	if isRunningAsAdmin() {
		return "Administrator"
	}
	return "Standard User"
}
