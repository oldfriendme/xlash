package main

import (
    "net/http"
    "net"
    "encoding/base64"
    "bytes"
    "io"
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
    "path/filepath"
    "regexp"
    "net/http/httputil"
    "syscall"
    "os/signal"
    "net/url"
    "sync"
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
    XhttpSettings XhttpSettings `json:"xhttpSettings"`
}

type TLSSettings struct {
    AllowInsecure bool     `json:"allowInsecure"`
    ServerName    string   `json:"serverName"`
    ALPN          []string `json:"alpn"`
    Fingerprint   string   `json:"fingerprint"`
}

type XhttpSettings struct {
    Path                  string `json:"path"`
    Host                  string `json:"host"`
    Mode                  string `json:"mode"`
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
    Usage      int      `json:"usage"`
    Extra      string   `json:"extra"`
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

type nativeProxy1 struct {
    ListenAddr string   `json:"listen"`
    Proxy      string   `json:"proxy"`
}

type nativeProxym struct {
    ListenAddr[] string   `json:"listen"`
    Proxy[]      string   `json:"proxy"`
}

type CNP struct {
    Name   string `yaml:"name"`
    Type   string `yaml:"type"`
    Server string `yaml:"server"`
    Port   int    `yaml:"port"`
    Auth   string `yaml:"auth"`
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
    dclash bool
    dcsh[] byte
    porxy *httputil.ReverseProxy
    localfile string
    gse[] byte
    localaddr string
    cmdcsh *exec.Cmd
    cshmm string
    osstartLock sync.Mutex
    localcfile string
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

func Init_OUTPUT_x_json(tagNum string,serv_ip string,out_uuid string,sni string,fp string,path string) string {
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
    pathfile:=path
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
            Network:  "xhttp",
            Security: "tls",
            TLSSettings: TLSSettings{
                AllowInsecure: false,
                ServerName:    sni,
                ALPN:          []string{"h3", "h2", "http/1.1"},
                Fingerprint:   fp,
            },
            XhttpSettings: XhttpSettings{
                Path:           pathfile,
                Host:           sni,
                Mode:           "stream-up",
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

func Init_xhttp(fp string,serv_ip[] string,sni[] string,path string) string {
       len:=len(serv_ip)
    json_init:="{\"log\": {\"access\": \"\",\"error\": \"\",\"loglevel\": \"warning\"},\"inbounds\": ["
    //(tagNum string,in_port int,in_uuid string) string
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
    //(tagNum string,serv_ip string,out_uuid string,sni string,fp string,path string)
    for i:=0;i<len;i++{
        err = Init_OUTPUT_x_json(strconv.Itoa(i),serv_ip[i],guuid,sni[i],fp,path)
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

func Init_xgrpc(fp string,serv_ip[] string,sni[] string,path string) string {
    len:=len(serv_ip)
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

func Make_naive1(serv_ip string,lisrenIP string) string {
    parts := strings.Split(guuid, ":")
    if len(parts) != 2 {
        log.Printf("ERR: user:passwd format err")
        return "nil"
    }
    cfg := nativeProxy1{
        ListenAddr:        lisrenIP,
        Proxy:             "https://"+guuid+"@"+serv_ip,
    }
    
    data, _ := json.MarshalIndent(cfg, "", "  ")
    return string(data)
}

func Make_naiveM(serv_ip[] string,auth[] string) string {
       lens:=len(serv_ip)
       lisrenIP:=make([]string,lens)
       startIP:=9293
       for i:=0;i<lens;i++ {
       at := strings.Split(auth[i], ":")
    if len(at) != 2 {
               log.Printf("ERR: user:passwd format err")
               return "nil"
       }
       lisrenIP[i]="socks://127.0.1.16:"+strconv.Itoa(startIP)
       startIP++
       }

       cfg := nativeProxym{
        ListenAddr:        make([]string, 0, lens),
        Proxy:             make([]string, 0, lens),
    }

       for i := 0; i < lens; i++ {
        cfg.ListenAddr = append(cfg.ListenAddr,lisrenIP[i])
        cfg.Proxy = append(cfg.Proxy, "https://"+auth[i]+"@"+serv_ip[i])
    }

    data, _ := json.MarshalIndent(cfg, "", "  ")
    return string(data)
}

func Init_naive(serv_ip[] string,auth[] string) string {
       lens:=len(serv_ip)
       if lens==1{
               return Make_naive1(serv_ip[0],"socks://127.0.1.16:"+strconv.Itoa(9292))
       } else {
               return Make_naiveM(serv_ip,auth)
       }
}

func yaml_Unmarshal(s string,p *CNP){
    s = strings.TrimSpace(s)

    parts := strings.Split(s, ",")
    fieldMap := map[string]string{}

    for _, part := range parts {
        kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
        if len(kv) != 2 {
            continue
        }
        key := strings.TrimSpace(kv[0])
        val := strings.TrimSpace(kv[1])
        val = strings.Trim(val, `"`)
        fieldMap[key] = val
    }

    p.Name = fieldMap["name"]
    p.Type = fieldMap["type"]
    p.Server = fieldMap["server"]
    fmt.Sscanf(fieldMap["port"], "%d", &p.Port)
    p.Auth = fieldMap["auth"]
}

func hookwj(conf[] byte) ([]byte,int) {
if bytes.Contains(conf, []byte("- name: xlash_base64_")) {
    conf = bytes.ReplaceAll(conf, []byte("\r"), []byte{})
    pos := bytes.Index(conf, []byte("- name: xlash_base64_"))
    var xlash bytes.Buffer
    for i:=pos+len("- name: xlash_base64_");i<len(conf);i++{
        if conf[i] == '\n' {
            break
        }
        xlash.WriteByte(conf[i])
    }
    dedata, err := base64.StdEncoding.DecodeString(string(xlash.Bytes()))
    if err != nil {
        log.Println("ERR: decode,", err)
        return []byte("{\"message\":\"Decode base64 err\"}"),-1
    }
    gse=dedata
    if Get_http_json() < 0{
        log.Println("ERR: update subscribe fail: ")
        return []byte("{\"message\":\"Decode base64 err\"}"),-1
    } else {
        return nil,1
    }
} else if bytes.Contains(conf, []byte("- name: xlash_np_")) {
    pos := bytes.Index(conf, []byte("- name: xlash_np_"))
    var xlash bytes.Buffer
    for i:=pos+len("- name: xlash_np_");i<len(conf);i++{
        if conf[i] == '-' {
            break
        }
        xlash.WriteByte(conf[i])
    }
    getbyte := bytes.ReplaceAll(xlash.Bytes(), []byte("\r"), []byte{})
    getbyte = bytes.ReplaceAll(getbyte, []byte("\n"), []byte(","))
    line := "name: " + string(getbyte)
    var p CNP
    yaml_Unmarshal(line, &p)
    if p.Type != "naiveproxy" {
        dclash=true
        dcsh=conf
        return nil,1
    }
       npNum:=1
       opos:=pos
        for {
            opos = bytes.Index(conf[opos+18:], []byte("- {name: xlash_np_"))
                if opos>0 {
                    npNum++
                } else {
                    break
                }
        }
    Name :=strings.Replace(p.Name, "xlash_np_", "", 1)
    rs:=gs("127.0.1.16:9292",Name)
    ol:=18+len(xlash.Bytes())
    rl:=len(rs)
    spl:=ol - rl
    guuid=p.Auth
    serv:=make([]string,1)
    serv[0]=p.Server+":"+strconv.Itoa(p.Port)
    errn := Init_naive(serv,nil)
    if spl < 0 || errn == "nil" {
        log.Printf("naive patch format err")
        dclash=true
        dcsh=conf
        return nil,1
    }
    rs=rs+strings.Repeat(" ", spl)
    for i:=0;i<ol-2;i++{
        conf[i+pos]=rs[i]
    }
    
if npNum !=1 {
       poss:=make([]int,npNum)
       mxlash_byte:=make([]int,npNum)
       opos=pos
       for i:=1;i<npNum;i++{
               opos = bytes.Index(conf[opos+18:], []byte("- {name: xlash_np_"))
               poss[i]=opos
       }
       np:=make([]CNP,npNum)
       np[0]=p
       poss[0]=pos

for i:=1;i<npNum;i++{
       var xlash2 bytes.Buffer
       for i:=poss[i]+17;i<len(conf);i++{
               if conf[i] == '-' {
                       break
               }
               xlash2.WriteByte(conf[i])
       }
       mxlash_byte[i]=len(xlash2.Bytes())
       getbyte = bytes.ReplaceAll(xlash2.Bytes(), []byte("\r"), []byte{})
       getbyte = bytes.ReplaceAll(getbyte, []byte("\n"), []byte(","))
       line := "name: " + string(getbyte)
       yaml_Unmarshal(line, &np[i])
       if np[i].Type != "naiveproxy" {
               dclash=true
               dcsh=conf
               return nil,1
       }
}
guuids:=make([]string,npNum)

for i:=1;i<npNum;i++{
       Name2 :=strings.Replace(np[i].Name, "xlash_np_", "", 1)
       rs2:=gs("127.0.1.16:"+strconv.Itoa(9292+i),Name2)
       ol2:=18+mxlash_byte[i]
       rl2:=len(rs2)
       spl2:=ol2 - rl2
       guuids[i]=np[i].Auth
       if spl2 < 0 {
               log.Printf("naive patch format err")
               dclash=true
               dcsh=conf
               return nil,1
       }
       rs2=rs2+strings.Repeat(" ", spl2)
       for j:=0;j<ol2-2;j++{
               conf[j+poss[i]]=rs2[j]
       }
}
       serv2:=make([]string,npNum)
       for i:=0;i<npNum;i++{
               serv2[i]=np[i].Server+":"+strconv.Itoa(np[i].Port)
       }

       errn = Init_naive(serv2,guuids)

}
    
    osstartLock.Lock()
    defer osstartLock.Unlock()
    err := os.WriteFile(localcfile+"/confignp.json", []byte(errn), 0600)
    if err != nil {
        log.Println("ERR: update subscribe err",err)
        return []byte("{\"message\":\"WriteFile err\"}"),-1
    }
    if cmdon {
        cmdPid.Process.Kill()
        cmdPid.Wait()
    }
    cmd := exec.Command(localfile+"/xlashnaive.exe",localcfile+"/confignp.json")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Start(); err != nil {
        log.Println("ERR: start np err:",err)
        return []byte("{\"message\":\"start err\"}"),-1
    }
    cmdPid = cmd
    cmdon = true
    dclash=true
    dcsh=conf
} else {
    dclash=true
    dcsh=conf
}
return nil,0
}

func clashAPI(w http.ResponseWriter, r *http.Request){
    authHeader := r.Header.Get("Authorization")
    if authHeader != "" {
        if strings.HasPrefix(authHeader, "Bearer ") {
            pw := strings.TrimPrefix(authHeader, "Bearer ")
            if cshmm != pw {
                cshmm = pw
            }
        }
    }
    if r.Method == http.MethodGet {
    if r.URL.Path == "/xlash" {
        token := r.URL.Query().Get("token")
    if token == "" {
        log.Println("WRAN: NO token")
        w.WriteHeader(404)
        return
    }
    
    if token != gtoken{
        log.Println("WRAN: token err: unexpected token",token)
        w.WriteHeader(404)
        return
    }
        w.Write(gse)
        return
    }}
    if r.Method == http.MethodPut {
        if r.URL.Path == "/configs" {
            req, err := io.ReadAll(r.Body)
            if err != nil {
                log.Println("ERR raed http:", err)
                w.WriteHeader(400)
                w.Write([]byte("{\"message\":\"get all\"}"))
                r.Body.Close()
                return
            }
            r.Body.Close()
            if bytes.HasPrefix(req, []byte("{\"path\":\"")) {
                file := bytes.ReplaceAll(req, []byte("\"}"), []byte{})
                file = bytes.ReplaceAll(file, []byte("{\"path\":\""), []byte{})
                conf, err := os.ReadFile(string(file))
                if err != nil {
                    log.Println("ERR: ReadFile:", err)
                    w.WriteHeader(400)
                    w.Write([]byte("{\"message\":\"readfile\"}"))
                    return
                }
                data ,errn := hookwj(conf)
                if errn < 0 {
                    w.WriteHeader(400)
                    w.Write(data)
                    return
                }
                resp, err := http.Get("http://"+localaddr+"/api/v1/client/subscribe?sysreq=updateconf&token="+gtoken)
                if err != nil {
                    fmt.Println("local api fail:", err)
                    w.WriteHeader(400)
                    w.Write([]byte("{\"message\":\"localapi err\"}"))
                    return
                }
                resp.Body.Close()
                w.WriteHeader(204)
            } else {
                urlZ := "http://127.9.8.1:8383/configs"
                requ, err := http.NewRequest(http.MethodPut, urlZ, bytes.NewBuffer(req))
                if err != nil {
                    log.Println("ERR read fail:", err)
                    w.WriteHeader(400)
                    w.Write([]byte("{\"message\":\"reqs\"}"))
                    return
                }
                if len(cshmm)>1{
                    requ.Header.Set("Authorization", "Bearer "+cshmm)
                }
                requ.Header.Set("Content-Type", "application/json")
                hc := &http.Client{}
                resp, err := hc.Do(requ)
                if err != nil {
                    log.Println("ERR: read fail:", err)
                    w.WriteHeader(400)
                    w.Write([]byte("{\"message\":\"httpdo\"}"))
                    return
                }
                rps, err := io.ReadAll(resp.Body)
                if err != nil {
                    log.Println("ERR: read fail:", err)
                    w.WriteHeader(400)
                    w.Write([]byte("{\"message\":\"read\"}"))
                    resp.Body.Close()
                    return
                }
                resp.Body.Close()
                w.WriteHeader(resp.StatusCode)
                w.Write(rps)
            }
            return
        }
    }
    if r.Method == http.MethodGet {
    if r.URL.Path == "/myversion" {
        resp, err := http.Get("http://127.9.8.1:8383/version")
        if err != nil {
            w.WriteHeader(400)
            w.Write([]byte("{\"message\":\"request fail\"}"))
            return
        }
        msg, err := io.ReadAll(resp.Body)
        if err != nil {
            w.WriteHeader(400)
            w.Write([]byte("{\"message\":\"read request\"}"))
            resp.Body.Close()
            return
        }
        resp.Body.Close()
        type rpe struct {
            Meta      bool  `json:"meta"`
            Version string `json:"version"`
            Xlash   string  `json:"xlash"`
        }
        var result rpe
        if err := json.Unmarshal(msg, &result); err != nil {
            w.WriteHeader(400)
            w.Write([]byte("{\"message\":\"Unmarshal json\"}"))
            return
        }
        result.Xlash = fmt.Sprintf("v%.2f", myVersion)
        res, _ := json.Marshal(result)
        w.WriteHeader(200)
        w.Write(res)
        w.Write([]byte("\r\n"))
        return
    }}
    porxy.ServeHTTP(w, r)
}

func Get_http_json() int{
    req, err := http.NewRequest("GET", UrlRemoteSub, nil)
    if err != nil {
        log.Println("ERR: Init http requst err:", err)
        return -1
    }
    req.Header.Set("User-Agent", "xlash/0.1 (Not like clash)")

    client := &http.Client{}
    
    resp, err := client.Do(req)
    if err != nil {
        log.Println("requst subscribe err, http err:", err)
        return -1
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Printf("HTTP err: StatusCode= %d\n", resp.StatusCode)
        return -2
    }
    var cfg remoteSub
    if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
        log.Println("get subscribe err:", err)
        return -3
    }
    if myVersion < cfg.MinVersion {
        log.Println("ERR: this version to old: Version must >=", cfg.MinVersion)
        return -4
    }
    if (len(cfg.ServerIP)-len(cfg.Sni)) != (len(cfg.Name)-len(cfg.Sni)) {
            log.Println("get subscribe format err: lens err")
            return -5
    }
    if (len(cfg.ServerIP)-len(cfg.Name)) != 0 {
            log.Println("get subscribe format err: lens err")
            return -6
    }
    guuid=cfg.UUID
    gusage=cfg.Usage
    if cfg.Mode == "xgrpc" {
        errn := Init_xgrpc(cfg.Fingerprint,cfg.ServerIP,cfg.Sni,cfg.Path)
        if errn != "nil" {
            md5num :=""
            if updateTime >0 {
            hash := md5.New()
            hash.Write([]byte(errn))
            md5num = hex.EncodeToString(hash.Sum(nil))
            } else {
                md5num=MakeToken(8)
            }
            if md5sum != md5num{
                //file changed
                log.Println("INFO: subscribe file changed, update subscribe")
                osstartLock.Lock()
                defer osstartLock.Unlock()
                err := os.WriteFile(localcfile+"/configx.json", []byte(errn), 0600)
                 if err != nil {
                    log.Println("ERR: update subscribe err",err)
                    return -10
                }
                if cmdon {
                    cmdPid.Process.Kill()
                    cmdPid.Wait()
                }
                cmd := exec.Command(localfile+"/xlashxray.exe", "-c",localcfile+"/configx.json")
                cmd.Stdout = os.Stdout
                cmd.Stderr = os.Stderr
                if err := cmd.Start(); err != nil {
                    log.Println("ERR: start xray err:",err)
                    return -11
                }
                cmdPid = cmd
                cmdon = true
                server_idx = len(cfg.ServerIP)
            }
            md5sum = md5num
            server_commit=cfg.Name
            gusage=cfg.Usage
            dclash=false
            
            for i := range server_commit {
                decode ,err := url.PathUnescape(server_commit[i])
                if err==nil{
                    server_commit[i]=decode
                }
            }
            return 0
        } else {
            log.Println("ERR: Init_xgrpc xray err")
            return -20
        }
    } else if cfg.Mode == "naive" {
    
    len:=len(cfg.ServerIP)
    errn :=""
    if len ==1 {
       errn = Init_naive(cfg.ServerIP,nil)
    } else {
            guuids:=make([]string,len)
            for i:=0;i<len;i++{
                       guuids[i]=guuid
            }
            errn = Init_naive(cfg.ServerIP,guuids)
    }
        if errn != "nil" {
            md5num :=""
            if updateTime >0 {
            hash := md5.New()
            hash.Write([]byte(errn))
            md5num = hex.EncodeToString(hash.Sum(nil))
            } else {
                md5num=MakeToken(8)
            }
            if md5sum != md5num{
                //file changed
                log.Println("INFO: subscribe file changed, update subscribe")
                osstartLock.Lock()
                defer osstartLock.Unlock()
                err := os.WriteFile(localcfile+"/confignp.json", []byte(errn), 0600)
                 if err != nil {
                    log.Println("ERR: update subscribe err",err)
                    return -10
                }
                if cmdon {
                    cmdPid.Process.Kill()
                    cmdPid.Wait()
                }
                cmd := exec.Command(localfile+"/xlashnaive.exe",localcfile+"/confignp.json")
                cmd.Stdout = os.Stdout
                cmd.Stderr = os.Stderr
                if err := cmd.Start(); err != nil {
                    log.Println("ERR: start naive err:",err)
                    return -11
                }
                cmdPid = cmd
                cmdon = true
                server_idx = 1
            }
            md5sum = md5num
            server_commit=cfg.Name
            gusage=cfg.Usage
            dclash=false
            for i := range server_commit {
                decode ,err := url.PathUnescape(server_commit[i])
                if err==nil{
                    server_commit[i]=decode
                }
            }
            return 0
        } else {
            log.Println("ERR: Init_naive err")
            return -20
        }
    } else if cfg.Mode == "xhttp" {
        errn := Init_xhttp(cfg.Fingerprint,cfg.ServerIP,cfg.Sni,cfg.Path)
        if errn != "nil" {
            md5num :=""
            if updateTime >0 {
            hash := md5.New()
            hash.Write([]byte(errn))
            md5num = hex.EncodeToString(hash.Sum(nil))
            } else {
             md5num=MakeToken(8)
            }
            if md5sum != md5num{
                //file changed
                log.Println("INFO: subscribe file changed, update subscribe")
                osstartLock.Lock()
                               defer osstartLock.Unlock()
                               err := os.WriteFile(localcfile+"/configx.json", []byte(errn), 0600)
                 if err != nil {
                    log.Println("ERR: update subscribe err",err)
                    return -10
                }
                if cmdon {
                                       cmdPid.Process.Kill()
                                       cmdPid.Wait()
                }
                cmd := exec.Command(localfile+"/xlashxray.exe", "-c",localcfile+"/configx.json")
                cmd.Stdout = os.Stdout
                               cmd.Stderr = os.Stderr
                               if err := cmd.Start(); err != nil {
                    log.Println("ERR: start xray err:",err)
                    return -11
                }
                cmdPid = cmd
                cmdon = true
                server_idx = len(cfg.ServerIP)
            }
            md5sum = md5num
            server_commit=cfg.Name
            gusage=cfg.Usage
            dclash=false
            for i := range server_commit {
                decode ,err := url.PathUnescape(server_commit[i])
                if err==nil{
                    server_commit[i]=decode
                }
            }
            return 0
        } else {
            log.Println("ERR: Init_xhttp xray err")
            return -20
        }
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
    myVersion=0.3
    var err error
    var confData[] byte
    var yamlData string
    configuration:=""
    if !strings.Contains(os.Args[1],".json"){
        if os.Args[1] == "-h" {
            fmt.Println("  -d string")
            fmt.Println("        set configuration directory")
            fmt.Println("  -f string")
            fmt.Println("        specify configuration file")
            fmt.Println("  -m    set geodata mode")
            fmt.Println("  -v    show current version of xlash")
            return
        }
        if len(os.Args) < 4 {
            log.Println("xlash [conf_file].json")
            return
        }
        confpath:=""
        for i:=1;i<len(os.Args);i++{
            if strings.Contains(os.Args[i],".yaml"){
                confpath = os.Args[i]
            }
            if strings.Contains(os.Args[i],"-d"){
                if i+1 < len(os.Args) {
                configuration = os.Args[i+1]
                }
            }
        }
        if len(confpath) < 1 {
            fmt.Println("  -d string")
            fmt.Println("        set configuration directory")
            fmt.Println("  -f string")
            fmt.Println("        specify configuration file")
            fmt.Println("  -m    set geodata mode")
            fmt.Println("  -v    show current version of xlash")
            return
        } 
        conf, err := os.ReadFile(confpath)
        if err != nil {
            log.Fatalf("Error reading config file: %v", err)
        }
        pos := bytes.Index(conf, []byte("external-controller: \""))
        if pos < 0 {
            pos = bytes.Index(conf, []byte("external-controller: "))
        if pos<0{
            log.Fatalf("Error reading external-controller:")
        }
        var fixyh bytes.Buffer
        fixyh.Write(conf[:pos])
        fixyh.Write([]byte("external-controller: \""))
        i:=0
        for i=pos+21;i<len(conf);i++{
            if conf[i] == '\n' || conf[i] == '\r' {
                fixyh.WriteByte('"')
                break
            }
            fixyh.WriteByte(conf[i])
        }
        fixyh.Write(conf[i:])
        
            conf=fixyh.Bytes()
            pos = bytes.Index(conf, []byte("external-controller: \""))
            if pos < 0 {
            log.Fatalf("Error reading external-controller:")
            }
            
        }
        yamlData = string(conf)
        var xlash bytes.Buffer
        for i:=pos+22;i<len(conf);i++{
            if conf[i] == '"' {
                break
            }
            xlash.WriteByte(conf[i])
        }
        if string(xlash.Bytes()) == "127.9.8.1:8383" {
            log.Fatalf("ERR: Can't use 127.9.8.1:8383")
        }
        tk:=MakeToken(12)
        cfg := Config{
            Token:        tk,
            RemoteSub:    "http://"+string(xlash.Bytes())+"/xlash?token="+tk,
            AutoUpdate:   -1,
            Local_Listen: string(xlash.Bytes()),
        }
        confData, _ = json.Marshal(cfg)
    } else {
    confData, err = os.ReadFile(os.Args[1])
    if err != nil {
        log.Fatalf("Error reading config file: %v", err)
    }
    }

    var cfg Config
    err = json.Unmarshal(confData, &cfg)
    if err != nil {
        log.Fatal(err)
    }
    osExec, err := os.Executable()
    if err != nil {
        log.Fatal(err)
    }
    updateTime=cfg.AutoUpdate
    UrlRemoteSub=cfg.RemoteSub
    gtoken=cfg.Token
    dclash=false
    targetURL, err := url.Parse("http://127.9.8.1:8383")// clash服务端地址
    if err != nil {
        log.Fatalf("ERR: reslov url fail: %v,your computer has bug", err)
    }
    porxy = httputil.NewSingleHostReverseProxy(targetURL)
    if updateTime >0 {
    go autoUpdate()
    }
    rand.Seed(time.Now().UnixNano())
    cuuid = uuid_NewString()
    localfile=filepath.Dir(osExec)
    localcfile=filepath.Join(localfile, ".config")
    log.Println("start server in",cfg.Local_Listen)
    info, err := os.Stat(localcfile)
    if os.IsNotExist(err) {
        err := os.Mkdir(localcfile, 0700)
        if err != nil {
            log.Fatalln("config file Can't be Write：", err)
            return
        }
        Setfile(localcfile)
    } else {
        if !info.IsDir() {
            os.Remove(localcfile)
            err := os.Mkdir(localcfile, 0700)
            if err != nil {
                log.Fatalln("config file Can't be Write：", err)
                return
            }
            Setfile(localcfile)
        }
    }
    localaddr=cfg.Local_Listen
    http.HandleFunc("/", clashAPI)
    http.HandleFunc("/api/v1/client/subscribe", httpRoute)
    if len(configuration)<1{
        configuration=localcfile
    }
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan,
    syscall.SIGINT,
    syscall.SIGTERM,
    syscall.SIGQUIT,
    syscall.SIGHUP,
    )
    
    cshON:=false
    if len(os.Args[1]) == 2{
        cmda:=os.Args[1]
        if cmda[0]=='-'{
        cshON=true
        go func(){
            confPath := filepath.Join(localcfile, "xlash_clash.yaml")

            yamldata := []byte("mixed-port: 7890\nallow-lan: false\nlog-level: info\nsecret: ''\nexternal-controller: \"127.9.8.1:8383\"\n")
            err := os.WriteFile(confPath, yamldata, 0600)
            if err != nil {
                log.Fatalln("ERR: WriteFile xlash_clash.yaml",err)
                return
            }
            ln, err := net.Listen("tcp", "127.9.8.1:8383")
            if err != nil {
                log.Printf("Meta alrealy running,try to kill")
                KillMeta(configuration)
            } else {
                ln.Close()
            }
            //fix bug when xalsh be forceStop and not clean
            Pexist ,err :=processExists("xlash")
            if err == nil {
                if Pexist{
                    Killcore(configuration)
                }
            }
            cmd := exec.Command(localfile+"/xlashclashmeta.exe", "-m", "-d",configuration,"-f",confPath)
            cmd.Stdout = os.Stdout
            cmd.Stderr = os.Stderr
            env := os.Environ()
            env = append(env, "SAFE_PATHS="+localcfile)
            cmd.Env = env
            if err := cmd.Start(); err != nil {
                log.Fatalln("can find clashcore",err)
            }
            cmdcsh = cmd
            time.Sleep(time.Second)
            data,errn:=hookwj([]byte(yamlData))
            if errn <0{
                log.Println("ERR: ",string(data))
            } else {
            resp, err := http.Get("http://"+localaddr+"/api/v1/client/subscribe?sysreq=updateconf&token="+gtoken)
            if err != nil {
                log.Println("local api fail:", err)
            }
            resp.Body.Close()
            }
            
            if os.PathSeparator == '\\' {
            go func(){
            time.Sleep(time.Second*5)
            subpid := cmdcsh.Process.Pid
            pidData := []byte(fmt.Sprintf("%d", subpid))
            os.WriteFile(localfile+"/resources/clash.pid", pidData, 0600)
            }()}
            cmdcsh.Wait()
            sigChan <- syscall.SIGTERM
        }()
    }}
    
    go Exitclean(sigChan,cshON)
    
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

func KillMeta(configuration string){
    if os.PathSeparator == '/' {
        cmd := exec.Command("/bin/killall","-9", "xlashclashmeta.exe")
        cmd.Run()
    } else {
        cmd := exec.Command("C:\\Windows\\System32\\taskkill.exe", "/im", "xlashclashmeta.exe","/f")
        cmd.Run()
    }
}

func Killcore(configuration string){
    if os.PathSeparator != '/' {
        cmd := exec.Command("C:\\Windows\\System32\\taskkill.exe", "/im", "xlashxray.exe","/f")
        cmd.Run()
        cmd2 := exec.Command("C:\\Windows\\System32\\taskkill.exe", "/im", "xlashnaive.exe","/f")
        cmd2.Run()
    } else {
        cmd := exec.Command("/bin/killall", "-9", "xlashxray.exe")
        cmd.Run()
        cmd2 := exec.Command("/bin/killall", "-9", "xlashnaive.exe")
        cmd2.Run()
    }
}

func processExists(name string) (bool, error) {
    var out bytes.Buffer
    var output string
if os.PathSeparator != '/' {
    cmd := exec.Command("C:\\Windows\\System32\\tasklist.exe")
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return false, err
    }
    output = strings.ToLower(out.String())
} else {
    cmd := exec.Command("/bin/ps","-ef")
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return false, err
    }
    output = strings.ToLower(out.String())
}
    return strings.Contains(output, name), nil
}

func Exitclean(sigChan <-chan os.Signal,csh bool){
    <-sigChan
    if cmdon {
        cmdPid.Process.Kill()
        cmdPid.Wait()
    }
    if csh {
        cmdcsh.Process.Kill()
        cmdcsh.Wait()
    }
    log.Println("xlash Process exit.")
    os.Exit(0)
}

func MakeToken(n int) string {
    letters := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    b := make([]byte, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}

func httpRoute(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    
    if token == "" {
        log.Println("WRAN: NO token")
        w.WriteHeader(404)
        return
    }
    
    if token != gtoken{
        log.Println("WRAN: token err: unexpected token",token)
        w.WriteHeader(404)
        return
    }
    
    sysreq := r.URL.Query().Get("sysreq")
    
    if sysreq != "" {
         host, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil {
            log.Println("ERR: reslov RemoteAddr Fail:", err)
            http.Error(w, "bad address", http.StatusBadRequest)
            return
        }
        if host == "127.0.0.1" || host == "::1" {
            if sysreq == "updateconf" {
                cshdye:=""
                if dclash {
                    cshdye=string(dcsh)
                } else {
                    cshdye=MakeYaml()
                }
                confPath := filepath.Join(localcfile, "xlash_clash.yaml")
                if !strings.Contains(cshdye, "external-controller: ") {
                    if strings.Contains(cshdye,"\r") {
                        cshdye = "external-controller: \"127.9.8.1:8383\"\r\n" + cshdye
                    } else {
                        cshdye = "external-controller: \"127.9.8.1:8383\"\n" + cshdye
                    }
                } else {
                    if !strings.Contains(cshdye, "external-controller: \"") {
        pos := strings.Index(cshdye, "external-controller: ")
        var fixyh bytes.Buffer
        fixyh.WriteString(cshdye[:pos])
        fixyh.Write([]byte("external-controller: \""))
        i:=0
        for i=pos+21;i<len(cshdye);i++{
            if cshdye[i] == '\n' || cshdye[i] == '\r' {
                fixyh.WriteByte('"')
                break
            }
            fixyh.WriteByte(cshdye[i])
        }
        fixyh.WriteString(cshdye[i:])
        
            cshdye=string(fixyh.Bytes())
                    }
                re := regexp.MustCompile(`external-controller:\s*"\d+\.\d+\.\d+\.\d+:\d+"`)
                replacement := `external-controller: "127.9.8.1:8383"`
                cshdye = re.ReplaceAllString(cshdye, replacement)
                }
                err := os.WriteFile(confPath, []byte(cshdye), 0600)
                 if err != nil {
                    log.Println("ERR: save xlash_clash.yaml fail",err)
                    http.Error(w, "ERR: save clash.yaml fail",500)
                    return
                }
                payload := map[string]string{
                    "path": confPath,
                }
                jsonData , err := json.Marshal(payload)
                if err != nil {
                    fmt.Println("ERR: JSON Marshal:", err)
                    return
                }
                urlZ := "http://127.9.8.1:8383/configs"
                req, err := http.NewRequest(http.MethodPut, urlZ, bytes.NewBuffer(jsonData))
                if err != nil {
                    fmt.Println("ERR: Request Fail:", err)
                     return
                }
                
                if len(cshmm)>1{
                    req.Header.Set("Authorization", "Bearer "+cshmm)
                }
                req.Header.Set("Content-Type", "application/json")

                client := &http.Client{}
                resp, err := client.Do(req)
                if err != nil {
                    fmt.Println("ERR: update Fail", err)
                    return
                }
                 resp.Body.Close()
            }
            return
        } else {
            log.Println("WRAN: API request form non-localhost:",host)
            http.Error(w, "Not localhost", 403)
            return
        }
    }
    
    if dclash {
        w.Write([]byte(dcsh))
        return
    }
    
    w.Write([]byte(MakeYaml()))
}

func MakeYaml() string {
        
    clash_byte, err := os.ReadFile(localfile+"/clash.yaml")
    if err != nil {
        log.Printf("ERR: Read clash.yaml fail: %v", err)
        return ""
    }
    
    parts := strings.SplitN(string(clash_byte), "{{clash_body}}", 2)
    
    if len(parts) < 2 {
        log.Println("ERR: clash.yaml format err with {{clash_body}}")
        return ""
    }
    
    clash_header:=strings.TrimSpace(parts[0])
    clash_ender := strings.TrimSpace(parts[1])
    var clash_body [4]string
    clash_body[0]="\nproxy-groups:\n  - name: 🚀 节点选择(已用流量:"
    clash_body[1]="M)\n    type: select\n    proxies:\n      - ♻️ 自动选择\n"
    clash_body[2]="      - 🎯 全球直连\n  - name: ♻️ 自动选择\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n"
    clash_body[3]="  - name: 手动档\n    type: select\n    proxies:\n      - ♻️ 自动选择\n"
    
    if strings.Contains(guuid,":"){
        server_ip :="127.0.1.16:9292"
        dn:="\n  "+gs(server_ip,server_commit[0])
        dm:="      - "+server_commit[0]+"\n"
        return clash_header+dn+clash_body[0]+strconv.Itoa(gusage)+clash_body[1]+dm+clash_body[2]+dm+clash_body[3]+dm+"  "+clash_ender
    } else {
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
    return clash_header+dn+clash_body[0]+strconv.Itoa(gusage)+clash_body[1]+dm+clash_body[2]+dm+clash_body[3]+dm+"  "+clash_ender
    }
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

func gs(serv_ip string,comit string) string{
    parts := strings.Split(serv_ip, ":")
    if len(parts) == 2 {
        serv_addr := parts[0] 
        port := parts[1]
    return "- {name: "+comit+", server: "+serv_addr+", port: "+port+", type: socks5}"
    } else {
        log.Println("Invalid server IP format:",serv_ip)
        return ""
    }
}
