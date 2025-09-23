package main

import (
    "net/http"
    "encoding/json"
    "strconv"
    "strings"
    "log"
    "os"
    "time"
    "crypto/md5"
    "encoding/hex"
    "os/exec"
    "math/rand"
    "fmt"
)

type Inbound struct {
    Tag      string   `json:"tag"`
    Port     int      `json:"port"`
    Listen   string   `json:"listen"`
    Protocol string   `json:"protocol"`
    Sniffing Sniffing `json:"sniffing"`
    Settings Settings `json:"settings"`
}

type Sniffing struct {
    Enabled      bool     `json:"enabled"`
    DestOverride []string `json:"destOverride"`
    RouteOnly    bool     `json:"routeOnly"`
}

type Settings struct {
    Clients    []Client `json:"clients"`
    Decryption string   `json:"decryption"`
}

type Client struct {
    ID    string `json:"id"`
    Level int    `json:"level"`
    Email string `json:"email"`
}

type Outbound struct {
    Tag            string          `json:"tag"`
    Protocol       string          `json:"protocol"`
    Settings       OutboundSettings `json:"settings"`
    StreamSettings StreamSettings   `json:"streamSettings"`
    Mux            Mux              `json:"mux"`
}

type OutboundSettings struct {
    Vnext []Vnext `json:"vnext"`
}

type Vnext struct {
    Address string `json:"address"`
    Port    int    `json:"port"`
    Users   []User `json:"users"`
}

type User struct {
    ID         string `json:"id"`
    AlterID    int    `json:"alterId"`
    Email      string `json:"email"`
    Security   string `json:"security"`
    Encryption string `json:"encryption"`
}

type StreamSettings struct {
    Network      string       `json:"network"`
    Security     string       `json:"security"`
    TLSSettings  TLSSettings  `json:"tlsSettings"`
    GrpcSettings GrpcSettings `json:"grpcSettings"`
}

type TLSSettings struct {
    AllowInsecure bool     `json:"allowInsecure"`
    ServerName    string   `json:"serverName"`
    ALPN          []string `json:"alpn"`
    Fingerprint   string   `json:"fingerprint"`
}

type GrpcSettings struct {
    Authority             string `json:"authority"`
    ServiceName           string `json:"serviceName"`
    MultiMode             bool   `json:"multiMode"`
    IdleTimeout           int    `json:"idle_timeout"`
    HealthCheckTimeout    int    `json:"health_check_timeout"`
    PermitWithoutStream   bool   `json:"permit_without_stream"`
    InitialWindowsSize    int    `json:"initial_windows_size"`
}

type Mux struct {
    Enabled     bool `json:"enabled"`
    Concurrency int  `json:"concurrency"`
}

type remoteSub struct {
    MinVersion float64  `json:"minVersion"`
    Mode       string   `json:"mode"`
    Fingerprint string  `json:"client-fingerprint"`
    ServerIP   []string `json:"serverip"`
    Sni        []string `json:"sni"`
    Name       []string `json:"name"`
    Path       string   `json:"path"`
    UUID       string   `json:"uuid"`
    Usage      int   `json:"usage"`
}

type Config struct {
    Token           string   `json:"token"`
    RemoteSub       string   `json:"remoteSub"`
    AutoUpdate      int      `json:"autoUpdate"`
    Local_Listen    string   `json:"local_Listen"`
}

type RouteX struct {
    Type        string   `json:"type"`
    InboundTag  []string `json:"inboundTag"`
    OutboundTag string   `json:"outboundTag"`
}



var (
    gtoken string
    updateTime int
    guuid string
    myVersion float64
    UrlRemoteSub string
    gusage int
    cuuid string
    md5sum string
    cmdPid *exec.Cmd
    cmdon bool
    server_commit[] string
    server_idx int
)

func Init_INPUT_json(tagNum string,in_port int,in_uuid string) string {
    inb := Inbound{
        Tag:      "in"+tagNum,
        Port:     in_port,
        Listen:   "127.0.1.16",
        Protocol: "vless",
        Sniffing: Sniffing{
            Enabled:      true,
            DestOverride: []string{"http", "tls"},
            RouteOnly:    false,
        },
        Settings: Settings{
            Clients: []Client{
                {
                    ID:    in_uuid,
                    Level: 0,
                    Email: "a@a.a",
                },
            },
            Decryption: "none",
        },
    }

    b, _ := json.MarshalIndent(inb, "", "  ")
    return string(b)
}

func Init_OUTPUT_json(tagNum string,serv_ip string,out_uuid string,sni string,fp string,path string) string {
    iport := strings.Split(serv_ip, ":")
    if len(iport) != 2 {
        return "nil"
    }
    prot,err:=strconv.Atoi(iport[1])
    if err != nil{
        return "nil"
    }
    if path[0]!='/'{
        return "nil"
    }
    pathfile:=path[1:]
    o := Outbound{
        Tag:      "proxy"+tagNum,
        Protocol: "vless",
        Settings: OutboundSettings{
            Vnext: []Vnext{
                {
                    Address: iport[0],
                    Port:    prot,
                    Users: []User{
                        {
                            ID:         out_uuid,
                            AlterID:    0,
                            Email:      "a@a.a",
                            Security:   "auto",
                            Encryption: "none",
                        },
                    },
                },
            },
        },
        StreamSettings: StreamSettings{
            Network:  "grpc",
            Security: "tls",
            TLSSettings: TLSSettings{
                AllowInsecure: false,
                ServerName:    sni,
                ALPN:          []string{"h3", "h2", "http/1.1"},
                Fingerprint:   fp,
            },
            GrpcSettings: GrpcSettings{
                Authority:           sni,
                ServiceName:         pathfile,
                MultiMode:           true,
                IdleTimeout:         60,
                HealthCheckTimeout:  20,
                PermitWithoutStream: false,
                InitialWindowsSize:  0,
            },
        },
        Mux: Mux{
            Enabled:     false,
            Concurrency: -1,
        },
    }

    b, _ := json.MarshalIndent(o, "", "  ")
    return string(b)
}

func Init_ROUTE_X(tag int) string{
    cfg := RouteX{
        Type:        "field",
        InboundTag:  []string{"in"+strconv.Itoa(tag)},
        OutboundTag: "proxy"+strconv.Itoa(tag),
    }
    
    data, _ := json.MarshalIndent(cfg, "", "  ")

    return string(data)
}

func Init_xgrpc(fp string,serv_ip[] string,sni[] string,path string,len int) string {
    json_init:="{\"log\": {\"access\": \"\",\"error\": \"\",\"loglevel\": \"warning\"},\"inbounds\": ["
    var err string
    Inport := 12701
    for i:=0;i<len;i++{
        err = Init_INPUT_json(strconv.Itoa(i),Inport,cuuid)
        json_init=json_init+err
        Inport++
        if i+1<len{
            json_init=json_init+","
        }
    }
    json_init=json_init+"],\"outbounds\": ["
    for i:=0;i<len;i++{
        err = Init_OUTPUT_json(strconv.Itoa(i),serv_ip[i],guuid,sni[i],fp,path)
        if err == "nil" {
            log.Println("ERR: Get subscribe format err.")
            return err
        }
        json_init=json_init+err
        if i+1<len{
            json_init=json_init+","
        }
    }
    json_init=json_init+",{\"tag\": \"block\",\"protocol\": \"blackhole\",\"settings\": {\"response\": {\"type\": \"http\"}}}],\"dns\": {\"hosts\": {\"dns.google\": \"8.8.8.8\",\"proxy.example.com\": \"127.0.0.1\"},\"servers\": [{\"address\": \"223.5.5.5\",\"domains\": ["
    for i:=0;i<len;i++{
        json_init=json_init+"\""+serv_ip[i]+"\""
        if i+1<len{
            json_init=json_init+","
        }
    }
    json_init=json_init+"]},{\"address\": \"223.5.5.5\",\"domains\": [\"geosite:cn\",\"geosite:geolocation-cn\"],\"expectIPs\": [\"geoip:cn\"]},\"1.1.1.1\",\"8.8.8.8\",\"https://dns.google/dns-query\"]},\"routing\": {\"domainStrategy\": \"AsIs\",\"rules\": [{\"type\": \"field\",\"ip\": [\"geoip:private\"],\"outboundTag\": \"block\"},{\"type\": \"field\",\"port\": \"443\",\"network\": \"udp\",\"outboundTag\": \"block\"},"
    for i:=0;i<len;i++{
        err = Init_ROUTE_X(i)
        json_init=json_init+err
        if i+1<len{
            json_init=json_init+","
        }
    }
    
    return json_init+"]}}"
}

func Get_http_json() int {
    req, err := http.NewRequest("GET", UrlRemoteSub, nil)
    if err != nil {
        log.Println("ERR: Init http requst err:", err)
        return -1
    }
    req.Header.Set("User-Agent", "xlash/0.1 (Not like clash)")
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("ERR: requst subscribe err, http err:", err)
        return -1
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Printf("ERR: HTTP err: StatusCode= %d\n", resp.StatusCode)
        return -2
    }
    var cfg remoteSub
    if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
        log.Println("ERR: get subscribe err:", err)
        return -3
    }
    if myVersion < cfg.MinVersion {
        log.Println("ERR: this version to old: Version must >=", cfg.MinVersion)
        return -4
    }
    if cfg.Mode == "xgrpc" {
        if (len(cfg.ServerIP)-len(cfg.Sni)) != (len(cfg.Name)-len(cfg.Sni)) {
            log.Println("ERR: get subscribe format err: lens err")
            return -5
        }
        if (len(cfg.ServerIP)-len(cfg.Name)) != 0 {
            log.Println("ERR: get subscribe format err: lens err")
            return -6
        }
        guuid=cfg.UUID
        gusage=cfg.Usage
        lens:=len(cfg.ServerIP)
        errn := Init_xgrpc(cfg.Fingerprint,cfg.ServerIP,cfg.Sni,cfg.Path,lens)
        if errn != "nil" {
            hash := md5.New()
            hash.Write([]byte(errn))
            md5num := hex.EncodeToString(hash.Sum(nil))
            if md5sum != md5num{
                //file changed
                log.Println("INFO: subscribe file changed, update subscribe")
                err := os.WriteFile("./configx.json", []byte(errn), 0600)
                 if err != nil {
                    log.Println("ERR: update subscribe err",err)
                    return -10
                }
                if cmdon {
                    cmdPid.Process.Kill()
                    cmdPid.Wait()
                }
                cmd := exec.Command("./xray.exe", "-c","configx.json")
                if err := cmd.Start(); err != nil {
                    log.Println("ERR: start xray err:",err)
                    return -11
                }
                cmdPid = cmd
                cmdon = true
                server_idx = lens
            }
            md5sum = md5num
            server_commit=cfg.Name
            gusage=cfg.Usage
            return 0
        } else {
            log.Println("ERR: Init_xgrpc xray err")
            return -20
        }
    } else if cfg.Mode == "naive" {
        //support later
        log.Println("support later: ", cfg.Mode)
        return -100
    } else if cfg.Mode == "tuic" {
        //support later,tuic port hopping
        log.Println("support later: ", cfg.Mode)
        return -100
    } else {
        log.Println("ERR: mode not support: ", cfg.Mode)
        return -100
    }
}

func autoUpdate(){
    for{
        if Get_http_json() < 0{
            log.Println("ERR: update subscribe fail: ")
        }
        time.Sleep(time.Duration(updateTime) * time.Second * 60)
    }
}

func main() {
    if len(os.Args) < 2 {
        log.Println("xlash [conf_file].json")
        return
    }
    myVersion=0.1
    confData, err := os.ReadFile(os.Args[1])
    if err != nil {
        log.Fatalf("Error reading config file: %v", err)
    }
    
    var cfg Config
    err = json.Unmarshal(confData, &cfg)
    if err != nil {
        log.Fatal(err)
    }
    updateTime=cfg.AutoUpdate
    UrlRemoteSub=cfg.RemoteSub
    gtoken=cfg.Token
    
    go autoUpdate()
    cuuid = uuid_NewString()
    
    log.Println("start server in",cfg.Local_Listen)

    http.HandleFunc("/api/v1/client/subscribe", httpRoute)
    err = http.ListenAndServe(cfg.Local_Listen,nil)
    if err != nil {
        log.Println("Error starting server:", err)
    }
}

func uuid_NewString() string {
    b := make([]byte, 16)
    for i := 0; i < 16; i++ {
        b[i] = byte(rand.Intn(256))
    }
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
        b[0:4],
        b[4:6],
        b[6:8],
        b[8:10],
        b[10:16],
    )
}

func httpRoute(w http.ResponseWriter, r *http.Request) {
    clash_byte, err := os.ReadFile("./clash.yaml")
    if err != nil {
        log.Printf("ERR: Read clash.yaml fail: %v", err)
        w.WriteHeader(404)
        return
    }
    parts := strings.SplitN(string(clash_byte), "{{clash_body}}", 2)
    if len(parts) < 2 {
        log.Println("ERR: clash.yaml format err with {{clash_body}}")
        w.WriteHeader(404)
        return
    }
    
    clash_header:=strings.TrimSpace(parts[0])
    clash_ender := strings.TrimSpace(parts[1])
    var clash_body [4]string
    clash_body[0]="\nproxy-groups:\n  - name: 🚀 节点选择(已用流量:"
    clash_body[1]="M)\n    type: select\n    proxies:\n      - ♻️ 自动选择\n"
    clash_body[2]="      - 🎯 全球直连\n  - name: ♻️ 自动选择\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n"
    clash_body[3]="  - name: 手动档\n    type: select\n    proxies:\n      - ♻️ 自动选择\n"
    
    
    
    token := r.URL.Query().Get("token")
    
    if token != gtoken{
        log.Println("WRAN: token err: unexpected token",token)
        w.WriteHeader(404)
        return
    }
    server_ip :=make([]string,server_idx)
    for i:=0;i<server_idx;i++{
    server_ip[i] ="127.0.1.16:"+strconv.Itoa(12701+i)
    }
    var dn string
    for i:=0;i<server_idx;i++ {
        dn=dn+gc(server_ip[i],server_commit[i],cuuid)
    }
    var dm string
    for i:=0;i<server_idx;i++ {
        dm+="      - "+server_commit[i]+"\n"
    }
    w.Write([]byte(clash_header+dn+clash_body[0]+strconv.Itoa(gusage)+clash_body[1]+dm+clash_body[2]+dm+clash_body[3]+dm+"  "+clash_ender))
}

func gc(serv_ip string,comit string,uuid string) string{
    addr := strings.Split(serv_ip, ":")
    if len(addr) == 2 {
    return "\n  - {name: "+comit+", server: "+addr[0]+", port: "+addr[1]+", client-fingerprint: chrome, type: vless, uuid: "+uuid+", tls: false, tfo: false, skip-cert-verify: false, network: tcp, udp: false}"
    } else {
        log.Println("Invalid server IP format:",serv_ip)
        return ""
    }
}
