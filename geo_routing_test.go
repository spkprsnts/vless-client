package main

import (
	"reflect"
	"testing"
)

// ruleSummary is the part of a routing rule these tests care about.
type ruleSummary struct {
	out, tag  string
	hasDomain bool
	hasIP     bool
	udp443    bool
}

func summarize(t *testing.T, rules []any) []ruleSummary {
	t.Helper()
	var got []ruleSummary
	for _, r := range rules {
		m := r.(map[string]any)
		s := ruleSummary{out: m["outboundTag"].(string)}
		s.tag, _ = m["ruleTag"].(string)
		_, s.hasDomain = m["domain"]
		_, s.hasIP = m["ip"]
		s.udp443 = m["network"] == "udp" && m["port"] == 443
		got = append(got, s)
	}
	return got
}

func TestBuildGeoRoutingMixedSplitsDomainAndIP(t *testing.T) {
	_, rules, strategy := buildGeoRouting("geosite:whitelist,geoip:whitelist,geosite:private,10.0.0.0/8", "", "", "")
	want := []ruleSummary{
		{out: "bypass-out", hasDomain: true},
		{out: "bypass-out", hasIP: true},
	}
	if got := summarize(t, rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %+v, want %+v", got, want)
	}
	m := rules[0].(map[string]any)
	if !reflect.DeepEqual(m["domain"], []string{"geosite:whitelist", "geosite:private"}) {
		t.Errorf("domain = %v", m["domain"])
	}
	if !reflect.DeepEqual(rules[1].(map[string]any)["ip"], []string{"geoip:whitelist", "10.0.0.0/8"}) {
		t.Errorf("ip = %v", rules[1].(map[string]any)["ip"])
	}
	if strategy != "IPIfNonMatch" {
		t.Errorf("domainStrategy = %q", strategy)
	}
}

func TestBuildGeoRoutingDomainsOnly(t *testing.T) {
	_, rules, strategy := buildGeoRouting("geosite:whitelist,example.com", "", "", "")
	want := []ruleSummary{{out: "bypass-out", hasDomain: true}}
	if got := summarize(t, rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %+v, want %+v", got, want)
	}
	if strategy != "AsIs" {
		t.Errorf("domainStrategy = %q, want AsIs", strategy)
	}
}

func TestBuildGeoRoutingIPOnly(t *testing.T) {
	_, rules, strategy := buildGeoRouting("geoip:private,1.2.3.4", "", "", "")
	want := []ruleSummary{{out: "bypass-out", hasIP: true}}
	if got := summarize(t, rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %+v, want %+v", got, want)
	}
	if strategy != "IPIfNonMatch" {
		t.Errorf("domainStrategy = %q, want IPIfNonMatch", strategy)
	}
}

func TestBuildGeoRoutingOrderAndTags(t *testing.T) {
	outbounds, rules, strategy := buildGeoRouting(
		"geosite:private,geoip:private",
		"geosite:ads,geoip:bad",
		"127.0.0.1:1081",
		"domain:youtube.com,1.1.1.1",
	)
	want := []ruleSummary{
		{out: "block-out", hasDomain: true},
		{out: "block-out", hasIP: true},
		{out: "block-out", tag: dpiQUICRuleTag, hasDomain: true, udp443: true},
		{out: "block-out", tag: dpiQUICIPRuleTag, hasIP: true, udp443: true},
		{out: dpiOutboundTag, tag: dpiRuleTag, hasDomain: true},
		{out: dpiOutboundTag, tag: dpiIPRuleTag, hasIP: true},
		{out: "bypass-out", hasDomain: true},
		{out: "bypass-out", hasIP: true},
	}
	if got := summarize(t, rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %+v\nwant     %+v", got, want)
	}
	// Xray refuses a repeated non-empty ruleTag.
	seen := map[string]bool{}
	for _, s := range summarize(t, rules) {
		if s.tag != "" && seen[s.tag] {
			t.Errorf("duplicate ruleTag %q", s.tag)
		}
		seen[s.tag] = true
		if s.tag != "" && !isDPIRuleTag(s.tag) {
			t.Errorf("ruleTag %q not recognised by isDPIRuleTag", s.tag)
		}
	}
	if len(outbounds) != 3 { // block-out, dpi-out, bypass-out
		t.Errorf("got %d outbounds, want 3", len(outbounds))
	}
	if strategy != "IPIfNonMatch" {
		t.Errorf("domainStrategy = %q", strategy)
	}
}
