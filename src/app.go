package main

import (
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"runtime"
)

var (
	gConfig    Config
	gTLSConfig tls.Config
	//	gConMap = NewConnectionMap()
)

type Config struct {
	Host     string `json:"host"`
	Timeout  int    `json:"timeout"`
	LogLevel int    `json:"log_level"`
}

func LoadConfig() error {
	// Read config.json
	file, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer func() {
		CloseFile(file)
	}()

	err = json.NewDecoder(file).Decode(&gConfig)
	if err != nil {
		return err
	}

	// Read certificates
	cert, err := tls.LoadX509KeyPair("cert.crt", "cert.key")
	if err != nil {
		return err
	}

	gTLSConfig.Certificates = []tls.Certificate{cert}

	return nil
}

func HandleSession(srcConn net.Conn) {
	// Handle current session
	slog.Info("new session",
		slog.String("from", srcConn.RemoteAddr().String()),
	)
	defer func() {
		CloseConnection(srcConn)
		slog.Debug("session closed", slog.Int("goroutine_num", runtime.NumGoroutine()))
	}()

	// Iterate over packets
	for {
		// Get operation code
		opcode, err := STCPGetOpCode(srcConn)
		if err != nil {
			slog.Error("STCPGetOpCode error", slog.String("err", err.Error()))
			return
		}

		if opcode == 0x01 { // 0x01 - REGISTER
			// Get target address and target port
			tgtAddr, tgtPort, err := STCPHandleRegister(srcConn)
			if err != nil {
				slog.Error("STCPHandleRegister error", slog.String("err", err.Error()))
				return
			}

			/*tgtHost := fmt.Sprintf("%s:%d", net.IP(tgtAddr).String(), binary.BigEndian.Uint16(tgtPort))
			tgtConn, err := net.DialTimeout("tcp", tgtHost, time.Duration(gConfig.Timeout)*time.Second)
			if err != nil {
				slog.Error("failed to connect to the target", slog.String("err", err.Error()))
				return
			}

			uid, err := gConMap.Register(tgtConn)
			if err != nil {
				slog.Error("failed to register connection", slog.String("err", err.Error()))
				CloseConnection(tgtConn)
				return
			}*/

			// Generate unique session identifier
			uid := make([]byte, 16)

			// Send UID to client
			err = STCPDoRegisterReply(srcConn, uid)
			if err != nil {
				slog.Error("STCPDoRegisterReply error", slog.String("err", err.Error()))
				// CloseConnection(tgtConn)
				return
			}

			slog.Info("0x01 - REGISTER", tgtAddr, tgtPort, uid)
			continue
		}

		if opcode == 0x02 { // 0x02 - CONTROL
			// Get UID
			uid, err := STCPHandleControl(srcConn)
			if err != nil {
				slog.Error("STCPHandleControl error", slog.String("err", err.Error()))
				return
			}

			// Reply successful control
			err = STCPDoControlReply(srcConn, true)
			if err != nil {
				slog.Error("STCPDoControlReply error", slog.String("err", err.Error()))
				return
			}

			slog.Info("0x02 - CONTROL", uid)
			return
		}

		slog.Error("unknown opcode", slog.Int("opcode", int(opcode)))
		return
	}
}

func main() {
	// Load config
	err := LoadConfig()
	if err != nil {
		slog.Error("failed to load config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	slog.SetLogLoggerLevel(slog.Level(gConfig.LogLevel))

	// Setup listener
	listener, err := tls.Listen("tcp", gConfig.Host, &gTLSConfig)
	if err != nil {
		slog.Error("failed to setup listener", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer func() {
		err = listener.Close()
		if err != nil {
			slog.Warn("failed to close listener", slog.String("err", err.Error()))
		}
	}()

	slog.Info("server started and ready to accept connections", slog.String("host", listener.Addr().String()))

	// Wait for connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("failed to accept connection", slog.String("err", err.Error()))
		} else {
			go HandleSession(conn)
		}
	}
}
