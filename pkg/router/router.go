package router

import (
	"context"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/vishvananda/netlink"
	"net"
	"os/exec"
	"strings"
)

const (
	MANAGERROUTETABLE    = 501
	MANAGERROUTEPREFER   = 501
	TOMANAGERROUTEPREFER = 502
	IPV4MASK             = 32
	IPV6MASK             = 128
	SRCPOOL              = "cloud-route-manager-src-pool"
	DSTPOOL              = "cloud-route-manager-dst-pool"
)

func CheckIfRuleExist(src, dst *net.IPNet, table, family int) (bool, *netlink.Rule, error) {
	ruleList, err := netlink.RuleList(family)
	if err != nil {
		return false, nil, fmt.Errorf("list subnet policy rules error: %v", err)
	}
	for _, rule := range ruleList {
		if (src != nil && src == rule.Src) || (src != nil && rule.Src != nil && src.String() == rule.Src.String()) ||
			(dst != nil && dst == rule.Dst) || (dst != nil && rule.Dst != nil && dst.String() == rule.Dst.String()) {
			if table > 0 {
				if rule.Table == table {
					// rule exist
					return true, &rule, nil
				}
			} else {
				// rule exist
				return true, &rule, nil
			}
		}
	}

	return false, nil, nil
}

func AddRule(src, dst *net.IPNet, table int, family int, prefer int) error {
	rule := netlink.NewRule()
	rule.Src = src
	rule.Dst = dst
	rule.Table = table
	rule.Priority = prefer
	rule.Family = family

	return netlink.RuleAdd(rule)
}

func DeleteRule(src, dst *net.IPNet, table int, family int) error {
	exist, rule, err := CheckIfRuleExist(src, dst, table, family)
	if err != nil {
		return err
	} else if !exist {
		return nil
	}
	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("delete subnet policy rules error: %v", err)
	}

	return nil
}

func ClearRouteTable(table int, family int) error {
	defaultRouteDst := defaultRouteDstByFamily(family)

	routeList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: table,
	}, netlink.RT_FILTER_TABLE)

	if err != nil {
		return fmt.Errorf("failed to list route for table %v: %v", table, err)
	}

	for _, r := range routeList {
		if r.Dst == nil {
			r.Dst = defaultRouteDst
		}

		if err = netlink.RouteDel(&r); err != nil {
			return fmt.Errorf("failed to delete route %v for table %v: %v", r.String(), table, err)
		}
	}
	return nil
}

func defaultRouteDstByFamily(family int) *net.IPNet {
	if family == netlink.FAMILY_V6 {
		return &net.IPNet{
			IP:   net.ParseIP("::").To16(),
			Mask: net.CIDRMask(0, 128),
		}
	}

	return &net.IPNet{
		IP:   net.ParseIP("0.0.0.0").To4(),
		Mask: net.CIDRMask(0, 32),
	}
}

func EnsureRoutes(gateway string, table int) error {
	if len(gateway) == 0 {
		return fmt.Errorf("gateway is empty")
	}
	err := netlink.RouteReplace(&netlink.Route{
		Dst:   defaultRouteDstByFamily(netlink.FAMILY_V4),
		Gw:    net.ParseIP(gateway),
		Table: table,
		Scope: netlink.SCOPE_UNIVERSE,
	})

	if err != nil {
		return fmt.Errorf("failed to add default route: %v", err)
	}

	return nil
}

func EnsureFromPolicyRoute(l log.Logger, managerNetwork, oldmanagerNetwork string, managerChanged bool) error {
	if !strings.Contains(managerNetwork, "/") {
		managerNetwork = fmt.Sprintf("%s/%s", managerNetwork, "32")
	}

	cidr, err := netlink.ParseIPNet(managerNetwork)
	if err != nil {
		level.Error(l).Log(
			"op", "setConfig",
			"error", err,
			"msg", "failed to parse managerNetwork",
			"managerNetwork", managerNetwork, // 添加具体的配置值作为上下文
		)
		return err
	}

	ruleExsit, _, err := CheckIfRuleExist(cidr, nil, MANAGERROUTETABLE, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to check rule (dst: %v, table: %v) exist: %v", managerNetwork, MANAGERROUTETABLE, err)
	}

	if !ruleExsit {
		level.Debug(l).Log("op", "setConfig", "msg", "rule not exist, create rule")
		if err := AddRule(cidr, nil, MANAGERROUTETABLE, netlink.FAMILY_V4, MANAGERROUTEPREFER); err != nil {
			return fmt.Errorf("failed to add rule (dst: %v, table: %v) exist: %v", cidr.String(), MANAGERROUTETABLE, err)
		}
	}

	if managerChanged {
		level.Debug(l).Log("op", "setConfig", "msg", "managerNetwork changed, delete old rule")
		oldSrc, _ := netlink.ParseIPNet(oldmanagerNetwork)
		if err := DeleteRule(oldSrc, nil, MANAGERROUTETABLE, netlink.FAMILY_V4); err != nil {
			return fmt.Errorf("failed to delete rule (dst: %v, table: %v) exist: %v", cidr.String(), MANAGERROUTETABLE, err)
		}
	}

	return nil
}

func EnsureToPolicyRoute(l log.Logger, cmpVip, oldCmpVip string, cmpVipChanged bool) error {
	if !strings.Contains(cmpVip, "/") {
		cmpVip = fmt.Sprintf("%s/%s", cmpVip, "32")
	}
	dst, err := netlink.ParseIPNet(cmpVip)
	if err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to parse cmpVip")
		return err
	}

	found, _, err := CheckIfRuleExist(nil, dst, MANAGERROUTETABLE, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to check rule (dst: %v, table: %v) exist: %v", cmpVip, MANAGERROUTETABLE, err)
	}
	if !found {
		level.Debug(l).Log("op", "setConfig", "msg", "rule not exist, create rule")
		if err := AddRule(nil, dst, MANAGERROUTETABLE, netlink.FAMILY_V4, TOMANAGERROUTEPREFER); err != nil {
			return fmt.Errorf("failed to add rule (dst: %v, table: %v) exist: %v", cmpVip, MANAGERROUTETABLE, err)
		}
	}

	if cmpVipChanged {
		level.Debug(l).Log("op", "setConfig", "msg", "cmpVip changed, delete old rule")
		oldDst, _ := netlink.ParseIPNet(oldCmpVip)
		if err := DeleteRule(nil, oldDst, MANAGERROUTETABLE, netlink.FAMILY_V4); err != nil {
			return fmt.Errorf("failed to delete rule (dst: %v, table: %v) exist: %v", oldCmpVip, MANAGERROUTETABLE, err)
		}
	}
	return nil
}

// createIPSet 创建 ipset
func createIPSet(ipList []string, setName string) error {
	// 创建 ipset
	cmd := exec.CommandContext(context.Background(), "ipset", "create", setName, "hash:ip")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create ipset: %v, output: %s", err, out)
	}

	// 添加 IP 地址到 ipset
	for _, ipStr := range ipList {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		cmd = exec.CommandContext(context.Background(), "ipset", "add", setName, ipStr)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add IP to ipset: %v, output: %s", err, out)
		}
	}

	return nil
}

// addIptablesRule 添加 iptables 规则
func addIptablesRule(srcSetName, dstSetName string) error {
	// 构建 iptables 规则
	cmd := exec.CommandContext(context.Background(), "iptables", "-t", "nat", "-A", "POSTROUTING",
		"-m", "set", "--match-set", srcSetName, "src",
		"-m", "set", "--match-set", dstSetName, "dst",
		"-j", "MASQUERADE", "--random-fully")

	// 执行 iptables 命令
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add iptables rule: %v, output: %s", err, out)
	}

	return nil
}

// checkAndDeleteExistingIptablesRules 检查并删除已存在的 iptables 规则
func checkAndDeleteExistingIptablesRules(srcSetName, dstSetName string) error {
	// 检查 iptables 规则是否存在
	cmdCheck := exec.CommandContext(context.Background(), "iptables", "-t", "nat", "-C", "POSTROUTING",
		"-m", "set", "--match-set", srcSetName, "src",
		"-m", "set", "--match-set", dstSetName, "dst",
		"-j", "MASQUERADE", "--random-fully")

	// 执行 iptables 检查命令
	if out, err := cmdCheck.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "No chain/target/match by that name") {
			// 规则不存在，无需删除
			return nil
		}
		return fmt.Errorf("failed to check iptables rule: %v, output: %s", err, out)
	}

	// 构建 iptables 规则删除命令
	cmdDelete := exec.CommandContext(context.Background(), "iptables", "-t", "nat", "-D", "POSTROUTING",
		"-m", "set", "--match-set", srcSetName, "src",
		"-m", "set", "--match-set", dstSetName, "dst",
		"-j", "MASQUERADE", "--random-fully")

	// 执行 iptables 删除命令
	if out, err := cmdDelete.CombinedOutput(); err != nil && !strings.Contains(string(out), "No chain/target/match by that name") {
		return fmt.Errorf("failed to delete iptables rule: %v, output: %s", err, out)
	}

	// 删除 ipset 资源
	if err := deleteIpsetResource(srcSetName); err != nil {
		return fmt.Errorf("failed to delete ipset resource %s: %v", srcSetName, err)
	}
	if err := deleteIpsetResource(dstSetName); err != nil {
		return fmt.Errorf("failed to delete ipset resource %s: %v", dstSetName, err)
	}

	return nil
}

func EnsureIptableRule(src, dst, oldSrc, oldDst string) error {
	var srcList []string
	var dstList []string
	srcList = append(srcList, strings.Split(src, ",")...)
	dstList = append(srcList, strings.Split(dst, ",")...)

	// 创建 ipset
	if err := createIPSet(srcList, SRCPOOL); err != nil {
		fmt.Printf("Failed to create srclist ipset: %v\n", err)
		return err
	}
	if err := createIPSet(dstList, DSTPOOL); err != nil {
		fmt.Printf("Failed to create dstlist ipset: %v\n", err)
		return err
	}

	// 构建 iptables 规则
	if err := addIptablesRule(SRCPOOL, DSTPOOL); err != nil {
		fmt.Printf("Failed to add iptables rule: %v\n", err)
		return err
	}

	return nil
}

func UpdateIptablesRule(l log.Logger, src, dst, oldSrc, oldDst string) error {
	newKey := src + dst
	oldKey := oldSrc + oldDst

	if newKey != oldKey {
		// 删除旧的规则
		if err := checkAndDeleteExistingIptablesRules(SRCPOOL, DSTPOOL); err != nil {
			level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to delete iptables rule")
			return err
		}
	} else {
		return nil
	}

	// 添加新的规则
	if err := EnsureIptableRule(src, dst, oldSrc, oldDst); err != nil {
		level.Error(l).Log("op", "setConfig", "error", err, "msg", "failed to ensure iptables rule")
		return err
	}

	return nil
}

// deleteIpsetResource 删除指定名称的ipset资源。
func deleteIpsetResource(setName string) error {
	// 构建删除 ipset 命令
	cmdDelete := exec.CommandContext(context.Background(), "ipset", "destroy", setName)

	// 执行删除 ipset 命令
	if out, err := cmdDelete.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete ipset resource: %v, output: %s", err, out)
	}

	return nil
}
