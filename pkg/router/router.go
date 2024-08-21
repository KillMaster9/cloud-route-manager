package router

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
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

func AddRule(src, dst string, mask int, table int, family int, prefer int) error {
	rule := netlink.NewRule()
	if len(src) != 0 {
		rule.Src = &net.IPNet{IP: net.ParseIP(src), Mask: net.CIDRMask(mask, 32)}
	}

	if len(dst) != 0 {
		rule.Dst = &net.IPNet{IP: net.ParseIP(dst), Mask: net.CIDRMask(mask, 32)}
	}

	rule.Table = table
	rule.Priority = prefer
	rule.Family = family

	return netlink.RuleAdd(rule)
}

func DeleteRule(src, dst string, mask int, table int, family int) error {
	var srcNet *net.IPNet
	var dstNet *net.IPNet

	if len(src) != 0 {
		srcNet = &net.IPNet{IP: net.ParseIP(src), Mask: net.CIDRMask(mask, 32)}
	}
	if len(dst) != 0 {
		dstNet = &net.IPNet{IP: net.ParseIP(dst), Mask: net.CIDRMask(mask, 32)}
	}

	exist, rule, err := CheckIfRuleExist(srcNet, dstNet, table, family)
	if err != nil {
		return err
	} else if !exist {
		return nil
	}
	if err := netlink.RuleDel(rule); err != nil {
		return fmt.Errorf("delete subnet policy rules error: %v", err)
	}

	return netlink.RuleAdd(rule)
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
