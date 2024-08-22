package config

import (
	"encoding/json"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"io/ioutil"
	"os"
)

const (
	CNIFILENAME = "/etc/10-kuryr.conflist"
)

type Config struct {
	BussinessVip    string `yaml:"bussinessVip"`
	ClusterId       string `yaml:"clusterId"`
	CmpVip          string `yaml:"cmpVip"`
	Cni             string `yaml:"cni"`
	DeployNode      string `yaml:"deployNode"`
	LvmDeviceClass  string `yaml:"lvmDeviceClass"`
	CmpVipGateway   string `yaml:"managerGateway"`
	ManagerNetwork  string `yaml:"managerNetwork"`
	BusinessNetwork string `yaml:"bussinessNetwork"`
}

type CNIConfig struct {
	Name       string `json:"name"`
	CniVersion string `json:"cniVersion"`
	Plugins    []struct {
		Type        string   `json:"type"`
		KuryrConf   string   `json:"kuryr_conf,omitempty"`
		Debug       bool     `json:"debug,omitempty"`
		ServiceCIDR []string `json:"serviceCIDR,omitempty"`
		HijackCIDR  []string `json:"hijackCIDR,omitempty"`
	} `json:"plugins"`
}

func UpdateCNIConfigFile(l log.Logger, hjckRoute string) (bool, error) {
	update := false
	// 读取配置文件
	data, err := ioutil.ReadFile(CNIFILENAME)
	if err != nil {
		if os.IsNotExist(err) {
			return update, nil
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
			for _, cidr := range plugin.HijackCIDR {
				if cidr == hjckRoute {
					return update, nil
				}
			}
			config.Plugins[i].HijackCIDR = []string{hjckRoute}
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
	return formattedData
}
