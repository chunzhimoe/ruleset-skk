const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../config/clash-party-ct-uk.js"), "utf8");
const main = vm.runInNewContext(source + "\nmain");
const override = (profile) => JSON.parse(JSON.stringify(main(structuredClone(profile))));
const outbound = "CT-UK · USB 4G";
const customHost = "na.gateway.spring.citi.com";
const processMatch = String.raw`PROCESS-NAME-REGEX,(?i)^(Claude( Helper( \x28(GPU|Plugin|Renderer)\x29)?)?|claude-ios-sim)$`;
const pathMatch = "PROCESS-PATH-REGEX,(?i)(^|/)Claude[.]app/Contents/";
const loopback = (process) => `AND,((${process}),(OR,((IP-CIDR,127.0.0.0/8,no-resolve),(IP-CIDR6,::1/128,no-resolve)))),DIRECT`;
const proxyDns = "https://1.1.1.1/dns-query#feth50";
const blockUdp = (selector) => `AND,((NETWORK,UDP),(${selector})),REJECT`;
const usbRoute = (selector) => [blockUdp(selector), `${selector},${outbound}`];
const existingAI = {
  type: "http", behavior: "classical", url: "https://example.test/custom-ai.txt"
};
const input = {
  rules: [
    "DOMAIN,blocked.test,REJECT",
    "RULE-SET,claude,Claude",
    "RULE-SET,grok,Grok",
    "RULE-SET,lancidr,DIRECT",
    "RULE-SET,google,Google",
    `DOMAIN,${customHost},DIRECT`,
    "DOMAIN-SUFFIX,citi.com,DIRECT",
    "GEOIP,CN,DIRECT",
    "MATCH,Other"
  ],
  "rule-providers": {
    claude: { type: "file", behavior: "classical", path: "./claude.txt" },
    grok: { type: "file", behavior: "classical", path: "./grok.txt" },
    ai_non_ip: existingAI
  },
  dns: {
    enable: true,
    nameserver: ["system"],
    "nameserver-policy": { "+.example.test": "system" }
  }
};
const result = override(input);
const processPattern = new RegExp(processMatch.split(",")[1].slice(4), "i");
for (const name of ["Claude", "Claude Helper", "Claude Helper (GPU)", "Claude Helper (Plugin)", "Claude Helper (Renderer)", "claude-ios-sim"]) {
  assert.match(name, processPattern);
}
for (const name of ["codex", "Claude Code URL Handler", "other-claude", "Claude Helper (Other)"]) {
  assert.doesNotMatch(name, processPattern);
}

assert.deepEqual(result.rules, [
  ...[
    processMatch, pathMatch,
    "PROCESS-PATH-REGEX,(?i)(^|/)Antigravity[.]app/Contents/", "PROCESS-NAME,agy"
  ].flatMap((process) => [loopback(process), ...usbRoute(process)]),
  ...[
    customHost, "google.com", "www.google.com", "antigravity-unleash.goog",
    "cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.sandbox.googleapis.com", "businessaicode.googleapis.com",
    "businessaicode.us.rep.googleapis.com", "businessaicode.eu.rep.googleapis.com",
    "businessaicode.mtls.googleapis.com"
  ].flatMap((host) => usbRoute(`DOMAIN,${host}`)),
  ...["claude.ai", "claude.com", "claudeusercontent.com", "anthropic.com", "antigravity.google"]
    .flatMap((host) => usbRoute(`DOMAIN-SUFFIX,${host}`)),
  "DOMAIN,blocked.test,REJECT",
  blockUdp("RULE-SET,claude"),
  `RULE-SET,claude,${outbound}`,
  blockUdp("RULE-SET,grok"),
  `RULE-SET,grok,${outbound}`,
  blockUdp("RULE-SET,ai_non_ip"),
  `RULE-SET,ai_non_ip,${outbound}`,
  blockUdp("RULE-SET,apple_intelligence_non_ip"),
  `RULE-SET,apple_intelligence_non_ip,${outbound}`,
  "RULE-SET,lancidr,DIRECT",
  "RULE-SET,google,Google",
  "DOMAIN-SUFFIX,citi.com,DIRECT",
  blockUdp("RULE-SET,ai_ip"),
  `RULE-SET,ai_ip,${outbound}`,
  "GEOIP,CN,DIRECT",
  "MATCH,Other"
]);
assert.deepEqual(result["rule-providers"].ai_non_ip, existingAI);
assert.deepEqual(result["rule-providers"].claude, input["rule-providers"].claude);
assert.equal(result["rule-providers"].ai_ip.url, "https://ruleset.skk.moe/Clash/ip/ai.txt");
assert.equal(result["rule-providers"].ai_ip.interval, 43200);
assert.equal(result["rule-providers"].apple_intelligence_non_ip.interval, 43200);
assert.equal(result.proxies[0].type, "direct");
assert.equal(result.proxies[0]["interface-name"], "feth50");
assert.equal(result.proxies[0].udp, false);
assert.deepEqual(result.dns.nameserver, input.dns.nameserver);
assert.equal(result.dns["nameserver-policy"]["+.example.test"], "system");
assert.equal(result.dns["nameserver-policy"][customHost], proxyDns);
assert.equal(result.dns["nameserver-policy"]["+.claude.ai"], proxyDns);
assert.equal(result.dns["nameserver-policy"]["+.claude.com"], proxyDns);
assert.equal(result.dns["nameserver-policy"]["+.claudeusercontent.com"], proxyDns);
assert.equal(result.dns["nameserver-policy"]["+.anthropic.com"], proxyDns);
assert.equal(result.dns["nameserver-policy"]["+.citi.com"], undefined);
assert.equal(result.dns["nameserver-policy"]["rule-set:claude"], proxyDns);
assert.equal(result.dns["nameserver-policy"]["rule-set:grok"], proxyDns);
assert.equal(result.dns["nameserver-policy"]["rule-set:ai_ip"], undefined);
assert.deepEqual(override(result), result);

const secondSource = fs.readFileSync(path.join(__dirname, "../config/clash-party-ufi2.js"), "utf8");
const secondMain = vm.runInNewContext(secondSource + "\nmain");
const secondOverride = (profile) => JSON.parse(JSON.stringify(secondMain(structuredClone(profile))));
const second = secondOverride(input);
const secondOutbound = "CT-UK · UFI 2";
const secondDns = "https://1.1.1.1/dns-query#feth52";
assert.deepEqual(second.proxies, [{
  name: secondOutbound, type: "direct", "interface-name": "feth52", "ip-version": "ipv4", udp: false
}]);
assert.deepEqual(second["rule-providers"], result["rule-providers"]);
assert.deepEqual(second.dns.nameserver, input.dns.nameserver);

const googleRule = second.rules.indexOf("RULE-SET,google,Google");
assert(googleRule >= 0);
for (const selector of [
  "DOMAIN,google.com",
  "DOMAIN,www.google.com",
  "DOMAIN-SUFFIX,antigravity.google",
  "DOMAIN,cloudcode-pa.googleapis.com",
  "DOMAIN,businessaicode.eu.rep.googleapis.com",
  "PROCESS-PATH-REGEX,(?i)(^|/)Antigravity[.]app/Contents/",
  "PROCESS-NAME,agy",
  "RULE-SET,claude",
  "RULE-SET,grok",
  "RULE-SET,ai_non_ip"
]) {
  const position = second.rules.indexOf(`${selector},${secondOutbound}`);
  assert(position > 0 && position < googleRule, selector);
  assert.equal(second.rules[position - 1], blockUdp(selector));
}
assert(second.rules.includes(`RULE-SET,ai_ip,${secondOutbound}`));
for (const host of [
  "google.com", "www.google.com", "+.antigravity.google", "antigravity-unleash.goog",
  "cloudcode-pa.googleapis.com", "rule-set:claude", "rule-set:ai_non_ip", customHost
]) {
  assert.equal(second.dns["nameserver-policy"][host], secondDns);
}
for (const host of [
  "+.google.com", "+.googleapis.com", "mail.google.com", "drive.google.com", "accounts.google.com", "rule-set:google"
]) {
  assert.equal(second.dns["nameserver-policy"][host], undefined);
}
assert(!second.rules.includes(`DOMAIN-SUFFIX,google.com,${secondOutbound}`));
assert.equal(second.dns["nameserver-policy"]["+.example.test"], "system");
const secondPolicies = Object.fromEntries(Object.entries(second.dns["nameserver-policy"])
  .map(([key, value]) => [key, value === secondDns ? proxyDns : value]));
assert.deepEqual({
  ...second,
  proxies: [{ ...second.proxies[0], name: outbound, "interface-name": "feth50" }],
  rules: second.rules.map((rule) => rule.replace(`,${secondOutbound}`, `,${outbound}`)),
  dns: { ...second.dns, "nameserver-policy": secondPolicies }
}, result);
assert.deepEqual(secondOverride(second), second);

const wifiInput = structuredClone(input);
wifiInput.rules.unshift("RULE-SET,wifi-call-hk,HK Calling", "RULE-SET,wifi-call-uk,UK Calling");
wifiInput["rule-providers"]["wifi-call-uk"] = {
  type: "inline", behavior: "classical", payload: ["DOMAIN,epdg.epc.mnc010.mcc234.pub.3gppnetwork.org"]
};
for (const [apply, label, network] of [
  [override, outbound, "feth50"],
  [secondOverride, secondOutbound, "feth52"]
]) {
  const wifi = apply(wifiInput);
  const callingOutbound = `${label} · Wi-Fi Calling`;
  assert(wifi.rules.includes(`RULE-SET,wifi-call-uk,${callingOutbound}`));
  assert(wifi.rules.includes("RULE-SET,wifi-call-hk,HK Calling"));
  assert(!wifi.rules.includes(blockUdp("RULE-SET,wifi-call-uk")));
  assert.deepEqual(wifi["rule-providers"]["wifi-call-uk"], wifiInput["rule-providers"]["wifi-call-uk"]);
  assert.equal(wifi.dns["nameserver-policy"]["rule-set:wifi-call-uk"], `https://1.1.1.1/dns-query#${network}`);
  assert.deepEqual(wifi.proxies.find(({ name }) => name === callingOutbound), {
    name: callingOutbound, type: "direct", "interface-name": network, "ip-version": "ipv4", udp: true
  });
  assert.equal(wifi.proxies.find(({ name }) => name === label).udp, false);
  assert.deepEqual(apply(wifi), wifi);
}
console.log("Both CT UK override checks passed");
