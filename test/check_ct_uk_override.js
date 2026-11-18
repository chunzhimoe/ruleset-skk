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
  loopback(processMatch),
  blockUdp(processMatch),
  `${processMatch},${outbound}`,
  loopback(pathMatch),
  blockUdp(pathMatch),
  `${pathMatch},${outbound}`,
  blockUdp(`DOMAIN,${customHost}`),
  `DOMAIN,${customHost},${outbound}`,
  blockUdp("DOMAIN-SUFFIX,claude.ai"),
  `DOMAIN-SUFFIX,claude.ai,${outbound}`,
  blockUdp("DOMAIN-SUFFIX,claude.com"),
  `DOMAIN-SUFFIX,claude.com,${outbound}`,
  blockUdp("DOMAIN-SUFFIX,claudeusercontent.com"),
  `DOMAIN-SUFFIX,claudeusercontent.com,${outbound}`,
  blockUdp("DOMAIN-SUFFIX,anthropic.com"),
  `DOMAIN-SUFFIX,anthropic.com,${outbound}`,
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
console.log("CT UK override checks passed");
