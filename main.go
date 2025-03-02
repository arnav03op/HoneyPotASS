package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"net/http"

	"github.com/sirupsen/logrus"
)


func initLogging() {
	file, err := os.OpenFile("honeypot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logrus.SetOutput(file)
	} else {
		logrus.Info("Failed to log to file, using default stderr")
	}
}


func flagPotentialAttacker(remoteAddr, username, details string) {
	file, err := os.OpenFile("attackers.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Errorf("Error opening attackers file: %v", err)
		return
	}
	defer file.Close()

	entry := fmt.Sprintf("Time: %s, IP: %s, Username: %s, Details: %s\n",
		time.Now().Format("2006-01-02 15:04:05"), remoteAddr, username, details)
	_, err = file.WriteString(entry)
	if err != nil {
		logrus.Errorf("Error writing to attackers file: %v", err)
		return
	}
	logrus.Infof("Flagged potential attacker: %s", entry)
	
	sendAlert(entry)
}

func isSuspiciousCommand(cmd string) bool {
	suspiciousKeywords := []string{
        "rm", "chmod", "cat", "wget", "curl", "nc", "netcat", "sudo", "su",
		"dd", "mkfs", "chown", "chgrp", "fdisk", "mkfs.ext4", "mount", "umount",
		"iptables", "firewall-cmd", "ncat", "masscan", "nmap", "tcpdump", "hping",
		"tshark", "wireshark", "ps", "top", "htop", "lsof", "kill", "killall",
		"systemctl", "service", "pkexec", "crontab", "at", "setuid", "setgid",
		"chattr", "openssl", "base64", "tar", "gzip", "bzip2", "unzip", "scp",
		"sftp", "ftp", "ssh", "python", "python3", "perl", "ruby", "java",
		"docker", "kubectl", "helm",                  
    }
	for _, kw := range suspiciousKeywords {
		if strings.Contains(cmd, kw) {
			return true
		}
	}
	return false
	
}

func startFrontendServer() {
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", fs)
	// Use port 8080 for the frontend; you can change this if needed.
	frontendPort := "8080"
	logrus.Infof("Frontend server listening on port %s", frontendPort)
	if err := http.ListenAndServe("0.0.0.0:"+frontendPort, nil); err != nil {
		logrus.Errorf("HTTP server error: %v", err)
	}
}


func main() {
	initLogging()

	
	if err := InitDatabase(); err != nil {
		logrus.Fatalf("Failed to initialize MongoDB: %v", err)
	}

	
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logrus.Info("Starting GoHoneypot...")

	go startFrontendServer()

	//const port = process.env.PORT || 4000

	port := os.Getenv("PORT")
	if port == "" {
		port = "2222" 
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:"+port)
	if err != nil {
		logrus.Fatalf("Error starting listener on port %s: %v", port, err)
	}
	defer listener.Close()
	logrus.Infof("Honeypot listening on port %s", port)

	
	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}


func handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	logrus.Infof("New connection from %s", remoteAddr)

	// Send an SSH banner to mimic a real SSH server.
	banner := "SSH-2.0-OpenSSH_7.4\r\n"
	_, err := conn.Write([]byte(banner))
	if err != nil {
		logrus.Errorf("Error sending banner to %s: %v", remoteAddr, err)
		return
	}

	reader := bufio.NewReader(conn)
	attemptCount := 0
	// adjust it jaisa mann kare
	threshold := 3 

	
	for {
		_, err = conn.Write([]byte("login: "))
		if err != nil {
			logrus.Errorf("Error sending login prompt to %s: %v", remoteAddr, err)
			return
		}
		username, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection with %s closed during username input.", remoteAddr)
			return
		}
		username = strings.TrimSpace(username)

		_, err = conn.Write([]byte("Password: "))
		if err != nil {
			logrus.Errorf("Error sending password prompt to %s: %v", remoteAddr, err)
			return
		}
		password, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection with %s closed during password input.", remoteAddr)
			return
		}
		password = strings.TrimSpace(password)

		logrus.Infof("Login attempt from %s | Username: %s | Password: %s", remoteAddr, username, password)
		attemptCount++

		// Store the login attempt in MongoDB.
		if err := AddLoginAttemptToDB(remoteAddr, username, password); err != nil {
			logrus.Errorf("Error storing login attempt in DB: %v", err)
		}

		if attemptCount >= threshold {
			flagPotentialAttacker(remoteAddr, username, "Exceeded login attempt threshold")
			fakeShell(conn, reader, remoteAddr, username)
			return
		} else {
			_, err = conn.Write([]byte("Login incorrect\r\n"))
			if err != nil {
				logrus.Errorf("Error sending login incorrect message to %s: %v", remoteAddr, err)
				return
			}
		}
	}
}


// func fakeShell(conn net.Conn, reader *bufio.Reader, remoteAddr, username string) {
// 	welcomeMsg := fmt.Sprintf("Welcome %s! You now have limited shell access. Type 'exit' to disconnect.\n", username)
// 	_, err := conn.Write([]byte(welcomeMsg))
// 	if err != nil {
// 		logrus.Errorf("Error sending welcome message to %s: %v", remoteAddr, err)
// 		return
// 	}

// 	for {
// 		_, err := conn.Write([]byte("$ "))
// 		if err != nil {
// 			logrus.Errorf("Error sending shell prompt to %s: %v", remoteAddr, err)
// 			break
// 		}

// 		cmd, err := reader.ReadString('\n')
// 		if err != nil {
// 			logrus.Infof("Connection closed by %s during shell session.", remoteAddr)
// 			break
// 		}
// 		cmd = strings.TrimSpace(cmd)
// 		logrus.Infof("Command from %s: %s", remoteAddr, cmd)

		
// 		if err := AddShellCommandToDB(remoteAddr, cmd); err != nil {
// 			logrus.Errorf("Error storing shell command in DB: %v", err)
// 		}

// 		// Check if the command is suspicious.
// 		if isSuspiciousCommand(cmd) {
// 			flagPotentialAttacker(remoteAddr, username, fmt.Sprintf("Suspicious command: %s", cmd))
// 		}

// 		if cmd == "exit" {
// 			_, _ = conn.Write([]byte("Bye!\n"))
// 			logrus.Infof("Session with %s ended", remoteAddr)
// 			break
// 		}

// 		response := fmt.Sprintf("bash: %s: command not found\n", cmd)
// 		_, err = conn.Write([]byte(response))
// 		if err != nil {
// 			logrus.Errorf("Error sending response to %s: %v", remoteAddr, err)
// 			break
// 		}
// 	}

// 	time.Sleep(1 * time.Second)
// }

func fakeShell(conn net.Conn, reader *bufio.Reader, remoteAddr, username string) {
	// Simulate a basic current working directory and a fake file system.
	cwd := "/" // current working directory
	// A simple fake file system: map of "full file path" to file content.
	fakeFS := map[string]string{
		"/etc/passwd":         "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash",
		"/var/log/auth.log":   "Mar 01 13:53:23 server sshd[1234]: Failed password for root from 192.0.2.1 port 22 ssh2",
		"/home/user/notes.txt": "This is a fake note file for demonstration purposes.",
	}

	// Welcome message with a help prompt.
	welcomeMsg := fmt.Sprintf("Welcome %s! You now have limited shell access.\nType 'help' for available commands, or 'exit' to disconnect.\n", username)
	_, err := conn.Write([]byte(welcomeMsg))
	if err != nil {
		logrus.Errorf("Error sending welcome message to %s: %v", remoteAddr, err)
		return
	}

	for {
		// Display prompt with current working directory.
		prompt := fmt.Sprintf("%s$ ", cwd)
		_, err := conn.Write([]byte(prompt))
		if err != nil {
			logrus.Errorf("Error sending shell prompt to %s: %v", remoteAddr, err)
			break
		}

		// Read command input.
		cmd, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection closed by %s during shell session.", remoteAddr)
			break
		}
		cmd = strings.TrimSpace(cmd)
		logrus.Infof("Command from %s: %s", remoteAddr, cmd)

		// Process the command.
		switch {
		case cmd == "exit":
			_, _ = conn.Write([]byte("Bye!\n"))
			logrus.Infof("Session with %s ended", remoteAddr)
			return
		case cmd == "help":
			helpText := "Available commands: help, ls, pwd, cd <dir>, cat <file>, exit\n"
			_, _ = conn.Write([]byte(helpText))
		case cmd == "pwd":
			_, _ = conn.Write([]byte(cwd + "\n"))
		case cmd == "ls":
			// List files in the fake file system that are in the current directory.
			var files []string
			for path := range fakeFS {
				// For simplicity, assume files are at root or in a single level directory.
				if cwd == "/" && strings.HasPrefix(path, "/") {
					files = append(files, path[1:]) // remove leading '/'
				} else if strings.HasPrefix(path, cwd) {
					files = append(files, strings.TrimPrefix(path, cwd))
				}
			}
			if len(files) == 0 {
				_, _ = conn.Write([]byte("No files found.\n"))
			} else {
				_, _ = conn.Write([]byte(strings.Join(files, "\n") + "\n"))
			}
		case strings.HasPrefix(cmd, "cat "):
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) < 2 {
				_, _ = conn.Write([]byte("Usage: cat <filename>\n"))
				continue
			}
			filename := strings.TrimSpace(parts[1])
			fullPath := cwd
			if cwd == "/" {
				fullPath = "/" + filename
			} else {
				fullPath = cwd + filename
			}
			if content, ok := fakeFS[fullPath]; ok {
				_, _ = conn.Write([]byte(content + "\n"))
			} else {
				_, _ = conn.Write([]byte(fmt.Sprintf("cat: %s: No such file or directory\n", filename)))
			}
		case strings.HasPrefix(cmd, "cd "):
			parts := strings.SplitN(cmd, " ", 2)
			if len(parts) < 2 {
				_, _ = conn.Write([]byte("Usage: cd <directory>\n"))
				continue
			}
			dir := strings.TrimSpace(parts[1])
			// For demonstration, allow only cd to "/" or a single level directory.
			if dir == "/" {
				cwd = "/"
			} else {
				cwd = "/" + dir + "/"
			}
			_, _ = conn.Write([]byte("Changed directory to " + cwd + "\n"))
		default:
			// For unknown commands, simulate a bash error.
			_, _ = conn.Write([]byte(fmt.Sprintf("bash: %s: command not found\n", cmd)))
		}

		// Log the command to MongoDB (if implemented).
		if err := AddShellCommandToDB(remoteAddr, cmd); err != nil {
			logrus.Errorf("Error storing shell command in DB: %v", err)
		}

		// Check if the command is suspicious.
		if isSuspiciousCommand(cmd) {
			flagPotentialAttacker(remoteAddr, username, fmt.Sprintf("Suspicious command: %s", cmd))
		}
	}

	time.Sleep(1 * time.Second)
}
