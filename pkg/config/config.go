package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

const (
	CNIFILENAME = "/etc/10-iveth.conflist"
)

type Config struct {
	BussinessVip     string `json:"bussinessVip" yaml:"bussinessVip"`
	ClusterId        string `json:"clusterId" yaml:"clusterId"`
	CmpVip           string `json:"cmpVip" yaml:"cmpVip"`
	Cni              string `json:"cni" yaml:"cni"`
	DeployNode       string `json:"deployNode" yaml:"deployNode"`
	LvmDeviceClass   string `json:"lvmDeviceClass" yaml:"lvmDeviceClass"`
	ManagerGateway   string `json:"managerGateway" yaml:"managerGateway"`
	ManagerNetwork   string `json:"managerNetwork" yaml:"managerNetwork"`
	BussinessNetwork string `json:"bussinessNetwork" yaml:"bussinessNetwork"`
	ExternalNetwork  string `json:"externalNetwork" yaml:"externalNetwork"`
}

type CNIConfig struct {
	Name       string `json:"name"`
	CniVersion string `json:"cniVersion"`
	Plugins    []struct {
		Type         string          `json:"type"`
		KuryrConf    string          `json:"kuryr_conf,omitempty"`
		Debug        bool            `json:"debug,omitempty"`
		ServiceCIDR  []string        `json:"serviceCIDR,omitempty"`
		HijackCIDR   []string        `json:"hijackCIDR,omitempty"`
		Capabilities map[string]bool `json:"capabilities,omitempty"`
	} `json:"plugins"`
}

func UpdateCNIConfigFile(l log.Logger, hjckRoute []string) (bool, error) {
	update := false
	trys := 0
	base := 1 * time.Second
	// 读取配置文件
again:
	data, err := ioutil.ReadFile(CNIFILENAME)
	if err != nil {
		if os.IsNotExist(err) {
			if trys >= 6 {
				level.Error(l).Log("CNI config file not found, please check the /etc/cni/net.d/")
				return update, nil
			}
			trys++
			level.Debug(l).Log("CNI config file not found, wait 15s....")
			time.Sleep(base << trys)
			goto again
		}

		level.Debug(l).Log("Error reading file:", err)
		return update, err
	}

	// 解析配置文件
	var config CNIConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		level.Debug(l).Log("Error unmarshaling JSON:", err)
		return update, err
	}

	// 修改 serviceCIDR 的值
	for i, plugin := range config.Plugins {
		if plugin.Type == "coordinator" {
			config.Plugins[i].HijackCIDR = hjckRoute
			break
		}
	}

	// 将修改后的数据编码为 JSON 格式
	updatedData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return update, err
	}

	// 写回文件
	err = ioutil.WriteFile(CNIFILENAME, updatedData, 0644)
	if err != nil {
		return update, err
	}
	level.Debug(l).Log("CNI config file updated successfully.", updatedData)

	return true, nil
}

func FormatData(data map[string]string) string {
	formattedData := ""
	for k, v := range data {
		formattedData += fmt.Sprintf("%s: %s\n", k, v)
	}
	fmt.Printf("configmap data: %s", formattedData)
	return formattedData
}

func UpdateHostsFile(newIP string) {
	// 打开 /etc/hosts 文件进行读取
	fileName := "/cloud-route-manager/hosts"
	file, err := os.OpenFile(fileName, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "cr.incloudos.com") {
			// 如果找到了目标域名，则替换 IP 地址
			parts := strings.Fields(line)
			if len(parts) > 1 {
				parts[0] = newIP // 替换 IP 地址
				line = strings.Join(parts, " ")
			}
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// 清空文件内容
	file.Truncate(0)
	file.Seek(0, 0)

	// 写入修改后的内容
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
	writer.Flush()

	fmt.Println("Hosts file updated successfully.")
}
