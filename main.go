package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

func menu() {
	fmt.Println("Simple Server Tools by QiYiming#6898")
	fmt.Println("1. Check the Server Status")
	fmt.Println("2. Check the SSL Certificate")
	fmt.Println("3. Check the IP Address")
	fmt.Println("4. About")
	fmt.Println("5. Exit")
}

func check_status() {
	fmt.Println("Check the Server Status")
	fmt.Println("Please enter the URL(Please Remove Protocol Header):")
	var url string
	fmt.Scanln(&url)
	fmt.Println("Checking...")
	//获取该URL服务器的IP地址
	ips, err := net.LookupIP(url)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	//向ipinfo.io发送请求
	resp, err := http.Get("https://ipinfo.io/" + ips[0].String() + "/json")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	//读取返回的json
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	//解析json
	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)
	//输出结果
	fmt.Println("IP:", result["ip"])
	//如果json包含bogen字段，则输出
	if result["bogon"] != nil {
		fmt.Println("这是一个本地IP!")
	} else {
		fmt.Println("组织:", result["org"])
		fmt.Println("城市:", result["city"])
		fmt.Println("区域:", result["region"])
		fmt.Println("国家:", result["country"])
		fmt.Println("时区:", result["timezone"])
		//如果json中包含anycast字段，则输出
		if result["anycast"] != nil {
			fmt.Println("使用Anycast:", result["anycast"])
		}
	}
	//向该URL发送请求，ua使用：SimpleServerTools/Dev，记录响应时间
	timer := time.Now()
	req, err := http.NewRequest("GET", "http://"+url, nil)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	req.Header.Set("User-Agent", "SimpleServerTools/Dev")
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	stop_time := time.Since(timer)
	fmt.Println("响应时间:", stop_time)
	//输出结果
	fmt.Println("状态码:", resp.StatusCode)
	fmt.Println("服务器:", resp.Header.Get("Server"))
	fmt.Println("标题:", resp.Header.Get("Title"))
	if result["org"] != nil && result["org"].(string) == "AS13335" {
		fmt.Println("CDN: Cloudflare")
	} else if result["org"] != nil && result["org"].(string) == "AS416625" {
		fmt.Println("CDN: Akamai Technologies")
	} else if result["org"] != nil && result["org"].(string) == "AS54113" {
		fmt.Println("CDN: Fastly")
	} else if result["org"] != nil && result["org"].(string) == "AS10576" {
		fmt.Println("CDN: CDnow")
	} else if result["org"] != nil && result["org"].(string) == "AS38107" {
		fmt.Println("CDN: CDNetworks")
	}

}

func check_ssl() {
	fmt.Println("Check the SSL Certificate")
	fmt.Println("Please enter the URL:")
	var url string
	fmt.Scanln(&url)
	fmt.Println("Checking...")
	//向该服务器发送一个https请求并且获取证书
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				var cert, err = x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				//输出证书信息
				fmt.Println("证书信息:")
				fmt.Println("证书版本:", cert.Version)
				fmt.Println("证书序列号:", cert.SerialNumber)
				fmt.Println("证书签名算法:", cert.SignatureAlgorithm)
				fmt.Println("证书签名:", cert.Signature)
				fmt.Println("证书签名者:", cert.Issuer)
				fmt.Println("证书有效期:", cert.NotBefore, "至", cert.NotAfter)
				fmt.Println("证书主体:", cert.Subject)
				fmt.Println("证书公钥算法:", cert.PublicKeyAlgorithm)
				fmt.Println("证书公钥:", cert.PublicKey)
				fmt.Println("证书扩展:", cert.Extensions)
				return nil
			},
		},
	}
	_, err := http.Get(url)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
}

func check_ip() {
	var url string
	fmt.Scanln(&url)
	fmt.Println("Checking...")
	//获取该URL服务器的IP地址
	ips, err := net.LookupIP(url)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("IP:", ips)
	//向ipinfo.io发送请求
	resp, err := http.Get("https://ipinfo.io/" + ips[0].String() + "/json")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	//读取返回的json
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	//解析json
	var result map[string]interface{}
	json.Unmarshal([]byte(body), &result)
	//输出结果
	fmt.Println("IP:", result["ip"])
	//如果json包含bogen字段，则输出
	if result["bogon"] != nil {
		fmt.Println("这是一个本地IP!")
	} else {
		fmt.Println("组织:", result["org"])
		fmt.Println("城市:", result["city"])
		fmt.Println("区域:", result["region"])
		fmt.Println("国家:", result["country"])
		fmt.Println("时区:", result["timezone"])
		//如果json中包含anycast字段，则输出
		if result["anycast"] != nil {
			fmt.Println("使用Anycast:", result["anycast"])
		}
	}
}

func about() {
	fmt.Println("Simple Server Tools")
	fmt.Println("Developed by: QiYiming#6898")
	fmt.Println("If you have any questions, please create a new issue on GitHub.")
	fmt.Println("GitHub:https://github.com/CodereInc/SimpleServerTools")
}

func main() {
	menu()
	//选择菜单
	var choice int
	fmt.Scanln(&choice)
	switch choice {
	case 1:
		check_status()
		break
	case 2:
		check_ssl()
		break
	case 3:
		check_ip()
		break
	case 4:
		about()
		break
	case 5:
		os.Exit(0)
	default:
		fmt.Println("Error: Invalid choice")
	}
}
