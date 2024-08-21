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
	"strconv"
	"strings"
)

const (
	MANAGERROUTETABLE    = 501
	MANAGERROUTEPREFER   = 501
	TOMANAGERROUTEPREFER = 502
	IPV4MASK             = 32
	IPV6MASK             = 128
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

	if len(cmpVip) == 0 || len(managerNetwork) == 0 {
		level.Error(l).Log("op", "setConfig", "error", "msg", "configuration is missing, cloud-router-manager will not function")
		return fmt.Errorf("configuration is missing, cloud-router-manager will not function")
	}

	if oldResource != nil && oldResource.Data["cmpVip"] != cmpVip {
		level.Debug(l).Log("op", "setConfig", "msg", "cmpVip changed, old cmpVip:", oldResource.Data["cmpVip"], "new cmpVip:", cmpVip)
		cmpVipChanged = true
	}

	if oldResource != nil && oldResource.Data["managerNetwork"] != managerNetwork {
		level.Debug(l).Log("op", "setConfig", "msg", "cmpVip changed, old cmpVip:", oldResource.Data["cmpVip"], "new cmpVip:", cmpVip)
		managerChanged = true
	}

	// ip rule add from managerNetwork/CIDR prefer 501 table 501
	if !strings.Contains(managerNetwork, "/") {
		managerNetwork = fmt.Sprintf("%s/%s", managerNetwork, "32")
	}
	cidr, err := netlink.ParseIPNet(managerNetwork)
	if err != nil {
		level.Error(l).Log(
			"op", "setConfig",
			"error", err,
			"msg", "failed to parse managerNetwork",
			"managerNetwork", config.ManagerNetwork, // 添加具体的配置值作为上下文
		)
		return err
	}
	mask := strings.Split(managerNetwork, "/")[1]
	maskInt, _ := strconv.Atoi(mask)
	ruleExsit, _, err := router.CheckIfRuleExist(cidr, nil, MANAGERROUTETABLE, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to check rule (dst: %v, table: %v) exist: %v", cmpVip, MANAGERROUTETABLE, err)
	}

	if !ruleExsit {
		level.Debug(l).Log("op", "setConfig", "msg", "rule not exist, create rule")
		if err := router.AddRule(cidr.String(), "", maskInt, MANAGERROUTETABLE, netlink.FAMILY_V4, MANAGERROUTEPREFER); err != nil {
			return fmt.Errorf("failed to add rule (dst: %v, table: %v) exist: %v", cidr.String(), MANAGERROUTETABLE, err)
		}
	}

	if managerChanged {
		level.Debug(l).Log("op", "setConfig", "msg", "managerNetwork changed, delete old rule")
		if err := router.DeleteRule(cidr.String(), "", maskInt, MANAGERROUTETABLE, netlink.FAMILY_V4); err != nil {
			return fmt.Errorf("failed to delete rule (dst: %v, table: %v) exist: %v", cidr.String(), MANAGERROUTETABLE, err)
		}
	}

	// ip rule add to cmpVip/CIDR prefer 502 table 501
	dst, err := netlink.ParseIPNet(fmt.Sprintf("%s/%s", cmpVip, "32"))
	if err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to parse cmpVip")
		return err
	}

	found, _, err := router.CheckIfRuleExist(nil, dst, MANAGERROUTETABLE, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to check rule (dst: %v, table: %v) exist: %v", cmpVip, MANAGERROUTETABLE, err)
	}
	if !found {
		level.Debug(l).Log("op", "setConfig", "msg", "rule not exist, create rule")
		if err := router.AddRule("", cmpVip, IPV4MASK, MANAGERROUTETABLE, netlink.FAMILY_V4, TOMANAGERROUTEPREFER); err != nil {
			return fmt.Errorf("failed to add rule (dst: %v, table: %v) exist: %v", cmpVip, MANAGERROUTETABLE, err)
		}
	}

	if cmpVipChanged {
		level.Debug(l).Log("op", "setConfig", "msg", "cmpVip changed, delete old rule")
		oldCmpVip := oldResource.Data["cmpVip"]
		if err := router.DeleteRule("", oldCmpVip, IPV4MASK, MANAGERROUTETABLE, netlink.FAMILY_V4); err != nil {
			return fmt.Errorf("failed to delete rule (dst: %v, table: %v) exist: %v", cmpVip, MANAGERROUTETABLE, err)
		}
	}

	// ip route add default via cmpVipGateway table MANAGERROUTETABLE
	if err := router.EnsureRoutes(config.CmpVipGateway, MANAGERROUTETABLE); err != nil {
		return fmt.Errorf("failed to ensure routes: %v", err)
	}

	return nil
}

func (c *Controller) MarkSynced(l log.Logger) {
	c.synced = true
	level.Info(l).Log("event", "stateSynced", "msg", "controller synced")
}
func main() {
	var (
		namespace  = flag.String("namespace", "kube-system", "config / icks-cluster-info namespace")
		configName = flag.String("config", "icks-cluster-info", "config / configmap of record route's name")
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file (only needed when running outside of k8s)")
		logLevel   = flag.String("log-level", "info", fmt.Sprintf("log level. must be one of: [%s]", logging.Levels.String()))
	)
	flag.Parse()

	logger, err := logging.Init(*logLevel)
	if err != nil {
		fmt.Printf("failed to initialize logging: %s\n", err)
		os.Exit(1)
	}

	level.Info(logger).Log("Cloud-route-manager controller starting ")

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
	//CMP容灾备份功能，在cmpVip发生改变时，触发此流程
	oldResource := c.Client.OldResource

	if len(icksConfig.CmpVip) == 0 {
		return fmt.Errorf("configuration cmpVip is missing, cloud-router-manager will not function")
	}

	if oldResource != nil && oldResource.Data["cmpVip"] == icksConfig.CmpVip {
		return nil
	}
	level.Info(l).Log("op", "setPodRoute", "msg", "start to set pod route")

	cmpVip := fmt.Sprintf("%s/%s", icksConfig.CmpVip, "32")
	_, err := netlink.ParseIPNet(fmt.Sprintf("%s/%s", cmpVip, "32"))
	if err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to parse cmpVip")
		return err
	}

	// Update CNI config file
	update, err := config.UpdateCNIConfigFile(l, cmpVip)
	if err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to update cni config file")
		return err
	}

	if update {
		level.Info(l).Log("op", "setConfig", "msg", "update cni config file")
		if err = c.Client.UpdateSystemPodRoute(); err != nil {
			level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to update system pod route")
			return err
		}
	}

	return nil
}
