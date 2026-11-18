const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../config/clash-party-ct-uk.js"), "utf8");
const main = vm.runInNewContext(source + "\nmain");
const override = (profile) => JSON.parse(JSON.stringify(main(structuredClone(profile))));
const outbound = "CT-UK · USB 4G";
const customHost = "na.gateway.spring.citi.com";
const existingAI = {
  type: "http", behavior: "classical", url: "https://example.test/custom-ai.txt"
};
const input = {
  rules: [
    "DOMAIN,blocked.test,REJECT",
    "RULE-SET,grok,Grok",
    "RULE-SET,google,Google",
    `DOMAIN,${customHost},DIRECT`,
    "DOMAIN-SUFFIX,citi.com,DIRECT",
    "GEOIP,CN,DIRECT",
    "MATCH,Other"
  ],
  "rule-providers": {
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

assert.deepEqual(result.rules, [
  `DOMAIN,${customHost},${outbound}`,
  "DOMAIN,blocked.test,REJECT",
  `RULE-SET,grok,${outbound}`,
  `RULE-SET,ai_non_ip,${outbound}`,
  `RULE-SET,apple_intelligence_non_ip,${outbound}`,
  "RULE-SET,google,Google",
  "DOMAIN-SUFFIX,citi.com,DIRECT",
  `RULE-SET,ai_ip,${outbound}`,
  "GEOIP,CN,DIRECT",
  "MATCH,Other"
]);
assert.deepEqual(result["rule-providers"].ai_non_ip, existingAI);
assert.equal(result["rule-providers"].ai_ip.url, "https://ruleset.skk.moe/Clash/ip/ai.txt");
assert.equal(result["rule-providers"].ai_ip.interval, 43200);
assert.equal(result["rule-providers"].apple_intelligence_non_ip.interval, 43200);
assert.equal(result.proxies[0]["interface-name"], "feth50");
assert.deepEqual(result.dns.nameserver, input.dns.nameserver);
assert.equal(result.dns["nameserver-policy"]["+.example.test"], "system");
assert.equal(result.dns["nameserver-policy"][customHost], "https://1.1.1.1/dns-query#feth50");
assert.equal(result.dns["nameserver-policy"]["+.citi.com"], undefined);
assert.equal(result.dns["nameserver-policy"]["rule-set:grok"], "https://1.1.1.1/dns-query#feth50");
assert.equal(result.dns["nameserver-policy"]["rule-set:ai_ip"], undefined);
assert.deepEqual(override(result), result);
console.log("CT UK override checks passed");
