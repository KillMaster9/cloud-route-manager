// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"cloud-route-manager/pkg/config"
	"cloud-route-manager/pkg/k8s"
	"cloud-route-manager/pkg/logging"
	"cloud-route-manager/pkg/router"
	"flag"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/vishvananda/netlink"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"
)

type Controller struct {
	Client *k8s.Client
	synced bool
	config *config.Config
}

func GetRouterController() Controller {
	return Controller{}
}

func (c *Controller) SetConfig(l log.Logger, cfg *config.Config) k8s.SyncState {
	level.Debug(l).Log("event", "startUpdate", "msg", "start of config update")
	defer level.Debug(l).Log("event", "endUpdate", "msg", "end of config update")

	if cfg == nil {
		level.Error(l).Log("op", "setConfig", "error", "no icks-cluster-info configuration in cluster", "msg", "configuration is missing, cloud-router-manager will not function")
		return k8s.SyncStateErrorNoRetry
	}

	if err := c.SetPolicyRoute(l, cfg); err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "applying new configuration failed")
		return k8s.SyncStateError
	}

	if err := c.SetPodRoute(l, cfg); err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "applying new configuration failed")
		return k8s.SyncStateError
	}
	c.config = cfg
	return k8s.SyncStateReprocessAll
}

func (c *Controller) SetPolicyRoute(l log.Logger, config *config.Config) error {
	cmpVipChanged := false
	managerChanged := false
	oldResource := c.Client.OldResource
	cmpVip := config.CmpVip
	managerNetwork := config.ManagerNetwork
	var oldmanagerNetwork string
	var oldCmpVip string

	// 访问cmpvip 和 部署集群的服务管理网必须配置
	if len(cmpVip) == 0 || len(managerNetwork) == 0 {
		level.Error(l).Log("op", "setConfig", "error", "msg", "cmpVip or managerNetwork is missing, cloud-router-manager will not function")
		return fmt.Errorf("configuration [cmpVip or managerNetwork] is missing, cloud-router-manager will not function")
	}

	if oldResource != nil && oldResource.Data["cmpVip"] != cmpVip {
		level.Debug(l).Log("op", "setConfig", "msg", "cmpVip changed, old cmpVip:", oldResource.Data["cmpVip"], "new cmpVip:", cmpVip)
		cmpVipChanged = true
		oldCmpVip = oldResource.Data["cmpVip"]
	}

	if oldResource != nil && oldResource.Data["managerNetwork"] != managerNetwork {
		level.Debug(l).Log("op", "setConfig", "msg", "cmpVip changed, old cmpVip:", oldResource.Data["cmpVip"], "new cmpVip:", cmpVip)
		managerChanged = true
		oldmanagerNetwork = oldResource.Data["managerNetwork"]
	}

	// ip rule add from managerNetwork/CIDR prefer 501 table 501
	if err := router.EnsureFromPolicyRoute(l, managerNetwork, oldmanagerNetwork, managerChanged); err != nil {
		return err
	}

	// ip rule add to cmpVip/CIDR prefer 502 table 501
	if err := router.EnsureToPolicyRoute(l, cmpVip, oldCmpVip, cmpVipChanged); err != nil {
		return err
	}

	if err := router.EnsureExternalNetworkToPolicyRoute(l, config, oldResource); err != nil {
		return fmt.Errorf("failed to ensure external network to policy route: %v", err)
	}

	// ip route add default via cmpVipGateway table MANAGERROUTETABLE
	if err := router.EnsureRoutes(config.ManagerGateway, router.MANAGERROUTETABLE); err != nil {
		return fmt.Errorf("failed to ensure routes: %v", err)
	}

	return nil
}

func (c *Controller) MarkSynced(l log.Logger) {
	c.synced = true
	level.Info(l).Log("event", "stateSynced", "msg", "controller-arm64-amd64-arm64-amd64-amd64-arm64-arm64-amd64 synced")
}
func main() {
	var (
		namespace  = flag.String("namespace", "kube-system", "config / icks-cluster-info namespace")
		configName = flag.String("config", "icks-cluster-info", "config / configmap of record route's name")
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file (only needed when running outside of k8s)")
		logLevel   = flag.String("log-level", "debug", fmt.Sprintf("log level. must be one of: [%s]", logging.Levels.String()))
	)
	flag.Parse()

	logger, err := logging.Init(*logLevel)
	if err != nil {
		fmt.Printf("failed to initialize logging: %s\n", err)
		os.Exit(1)
	}

	level.Info(logger).Log("Cloud-route-manager controller-arm64-amd64-arm64-amd64-amd64-arm64-arm64-amd64 starting ")

	if *namespace == "" {
		bs, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			level.Error(logger).Log("op", "startup", "msg", "Unable to get namespace from pod service account data, please specify --namespace ", "error", err)
			os.Exit(1)
		}
		*namespace = string(bs)
	}
	c := GetRouterController()

	client, err := k8s.New(&k8s.Config{
		ProcessName:   "cloud-router-manager",
		ConfigMapName: *configName,
		ConfigMapNS:   *namespace,
		Logger:        logger,
		Kubeconfig:    *kubeconfig,
		ConfigChanged: c.SetConfig,
		Synced:        c.MarkSynced,
	})
	if err != nil {
		level.Error(logger).Log("op", "startup", "error", err, "msg", "failed to create k8s client")
		os.Exit(1)
	}

	c.Client = client

	if err := client.Run(nil); err != nil {
		level.Error(logger).Log("op", "startup", "error", err, "msg", "failed to run k8s client")
	}

}

func (c *Controller) SetPodRoute(l log.Logger, icksConfig *config.Config) error {
	var oldCmpVip string
	var oldBusinessNetwork string
	var oldSubnetList []string
	var subnetList []string
	oldSubnetMap := make(map[string]string)
	newSubnetMap := make(map[string]string)

	if icksConfig.Cni != "iveth" {
		return nil
	}

	//CMP容灾备份功能，在cmpVip发生改变时，触发此流程
	oldResource := c.Client.OldResource

	if len(icksConfig.CmpVip) == 0 {
		return fmt.Errorf("configuration cmpVip is missing, cloud-router-manager will not function")
	}

	if oldResource != nil && oldResource.Data["cmpVip"] == icksConfig.CmpVip && oldResource.Data["bussinessNetwork"] == icksConfig.BussinessNetwork && oldResource.Data["externalNetwork"] == icksConfig.ExternalNetwork {
		return nil
	}
	level.Info(l).Log("op", "setPodRoute", "msg", "start to set pod route")

	if oldResource != nil {
		oldCmpVip = fmt.Sprintf("%s/%s", oldResource.Data["cmpVip"], "24")
		oldBusinessNetwork = oldResource.Data["bussinessNetwork"]
		if val, ok := oldResource.Data["externalNetwork"]; ok {
			oldSubnetMap, oldSubnetList = router.ParseExternalConfig(val)
		}
		oldSubnetMap["cmpVip"] = oldCmpVip
		oldSubnetList = append(oldSubnetList, oldCmpVip)
	}

	cmpVip := fmt.Sprintf("%s/%s", icksConfig.CmpVip, "24")
	_, err := netlink.ParseIPNet(cmpVip)
	if err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to parse cmpVip")
		return err
	}

	newSubnetMap, subnetList = router.ParseExternalConfig(icksConfig.ExternalNetwork)
	newSubnetMap["cmpVip"] = cmpVip
	subnetList = append(subnetList, cmpVip)

	// Update CNI config file
	update, err := config.UpdateCNIConfigFile(l, subnetList)
	if err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to update cni config file")
		return err
	}
	time.Sleep(10 * time.Second)

	cmpVipChanged, err := router.CheckCmpVIPChanged(newSubnetMap, oldSubnetMap)
	if err != nil {
		return err
	}
	if cmpVipChanged {
		level.Info(l).Log("op", "setConfig", "msg", "update cni config file")
		// update hosts file
		config.UpdateHostsFile(icksConfig.CmpVip)
		// CRI to sync network config from confDir periodically to detect network config updates in every 5 seconds
	}

	if update {
		if err = c.Client.UpdateSystemPodRoute(newSubnetMap, oldSubnetMap, cmpVipChanged); err != nil {
			level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to update system pod route")
			return err
		}
	}
	sort.Strings(subnetList)
	sort.Strings(oldSubnetList)
	newSubnetStr := strings.Join(subnetList, ",")
	oldSubnetStr := strings.Join(oldSubnetList, ",")
	if err = router.UpdateIptablesRule(l, icksConfig.BussinessNetwork, newSubnetStr, oldBusinessNetwork, oldSubnetStr); err != nil {
		return err
	}

	return nil
}
