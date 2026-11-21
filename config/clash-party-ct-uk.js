// Clash Party subscription override for a CT UK USB connection on macOS.
const useSecondUfi = false;
const easyTierRelay = null;

function main(config) {
  if (!Array.isArray(config.rules)) return config;

  const outbound = useSecondUfi ? "CT-UK · UFI 2" : "CT-UK · USB 4G";
  const usbInterface = useSecondUfi ? "feth52" : "feth50";
  const wifiCallingProvider = "wifi-call-uk";
  const wifiCallingOutbound = `${outbound} · Wi-Fi Calling`;
  const ntpOutbound = `${outbound} · NTP`;
  const ntpRule = `AND,((NETWORK,UDP),(DST-PORT,123)),${ntpOutbound}`;
  const aiProcesses = [
    String.raw`PROCESS-NAME-REGEX,(?i)^(Claude( Helper( \x28(GPU|Plugin|Renderer)\x29)?)?|claude-ios-sim)$`,
    "PROCESS-PATH-REGEX,(?i)(^|/)Claude[.]app/Contents/",
    "PROCESS-PATH-REGEX,(?i)(^|/)Antigravity[.]app/Contents/",
    "PROCESS-NAME,agy"
  ];
  const routedDomains = [
    "claude.ai", "claude.com", "claudeusercontent.com", "anthropic.com", "antigravity.google",
    "clau.de", "claudemcpclient.com", "claudemcpcontent.com",
    "anthropic.com.cdn.cloudflare.net", "servd-anthropic-website.b-cdn.net",
    "anthropic.auth0.com", "anthropic-com.ghost.io",
    "sentry.io", "statsigapi.net", "browser-intake-us5-datadoghq.com",
    "intercom.io", "intercomcdn.com", "cdn.usefathom.com", "maps.googleapis.com",
    "withpersona.com", "frompersona.com"
  ];
  const routedHosts = [
    "na.gateway.spring.citi.com", "google.com", "www.google.com",
    "antigravity-unleash.goog", "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com", "daily-cloudcode-pa.sandbox.googleapis.com",
    "businessaicode.googleapis.com", "businessaicode.us.rep.googleapis.com",
    "businessaicode.eu.rep.googleapis.com", "businessaicode.mtls.googleapis.com"
  ];
  const exactDomainRules = routedHosts.map((host) => `DOMAIN,${host},`);
  const suffixRules = routedDomains.map((host) => `DOMAIN-SUFFIX,${host},`);
  const claudeTelemetry = "claude-code-telemetry";
  const claudeIpRules = [
    `IP-CIDR,160.79.104.0/21,${outbound},no-resolve`,
    "IP-CIDR6,2607:6bc0::/32,REJECT,no-resolve",
    `IP-ASN,399358,${outbound},no-resolve`
  ];
  const scopedDomainRules = [
    ...exactDomainRules.map((rule) => rule + outbound),
    ...suffixRules.map((rule) => rule + outbound),
    `RULE-SET,${claudeTelemetry},${outbound}`
  ];
  const leadingRules = [
    ntpRule,
    ...aiProcesses.flatMap((process) => [
      `AND,((${process}),(OR,((IP-CIDR,127.0.0.0/8,no-resolve),(IP-CIDR6,::1/128,no-resolve)))),DIRECT`,
      `${process},${outbound}`
    ]),
    ...scopedDomainRules
  ];
  const generatedRules = new Set([...leadingRules, ...claudeIpRules]);
  const sukka = "https://ruleset.skk.moe/Clash";
  const sukkaProviders = {
    ai_non_ip: `${sukka}/non_ip/ai.txt`,
    apple_intelligence_non_ip: `${sukka}/non_ip/apple_intelligence.txt`,
    ai_ip: `${sukka}/ip/ai.txt`
  };
  const aiProviders = new Set([
    "openai", "claude", "grok", "gemini", "ai", ...Object.keys(sukkaProviders)
  ]);
  const matchedProviders = new Set();
  const providers = (config["rule-providers"] ||= {});
  providers[claudeTelemetry] = {
    type: "inline", behavior: "classical",
    payload: ["DOMAIN-KEYWORD,datadog", "DOMAIN-KEYWORD,sentry", "DOMAIN-KEYWORD,sift"]
  };
  const existingRules = config.rules.filter((rule) =>
    typeof rule !== "string" ||
      (!generatedRules.has(rule) && !exactDomainRules.some((prefix) => rule.startsWith(prefix)))
  );
  const rules = existingRules.map((rule) => {
    if (typeof rule !== "string") return rule;
    const parts = rule.split(",");
    const provider = parts[1]?.trim();
    if (parts.length < 3 || parts[0].trim() !== "RULE-SET") return rule;
    const wifiCalling = provider === wifiCallingProvider && providers[provider];
    if (!wifiCalling && !aiProviders.has(provider)) return rule;
    matchedProviders.add(provider);
    parts[2] = wifiCalling ? wifiCallingOutbound : outbound;
    return parts.join(",");
  });
  // Preserve the subscription's specific rules ahead of the new AI domain rules.
  const broadRule = /^(?:RULE-SET,(?:lancidr|streamingip|google|apple|microsoft|global|domestic|direct),|GEOIP,|MATCH,)/;
  const domainBoundary = rules.findIndex((rule) => broadRule.test(rule));
  const domainRules = ["ai_non_ip", "apple_intelligence_non_ip"]
    .filter((name) => !matchedProviders.has(name))
    .map((name) => `RULE-SET,${name},${outbound}`);
  rules.splice(domainBoundary < 0 ? rules.length : domainBoundary, 0, ...domainRules, ...claudeIpRules);
  if (!matchedProviders.has("ai_ip")) {
    const ipBoundary = rules.findIndex((rule) => /^(GEOIP|MATCH),/.test(rule));
    rules.splice(ipBoundary < 0 ? rules.length : ipBoundary, 0, `RULE-SET,ai_ip,${outbound}`);
  }

  for (const [name, url] of Object.entries(sukkaProviders)) {
    matchedProviders.add(name);
    providers[name] ??= {
      type: "http", behavior: "classical", format: "text", interval: 43200,
      url, path: `./ruleset/${name}.txt`
    };
  }

  // Block scoped UDP before it can reach a macOS outbound or a later rule.
  const outgoingRules = [...leadingRules, ...rules];
  const udpBlocks = new Map();
  for (const rule of outgoingRules) {
    if (typeof rule !== "string") continue;
    const [type, value, target, ...flags] = rule.split(",");
    if (target !== outbound || !/^(DOMAIN|DOMAIN-SUFFIX|PROCESS-(NAME|PATH)(-REGEX)?|RULE-SET|IP-CIDR|IP-ASN)$/.test(type)) continue;
    const selector = [type, value, ...flags].join(",");
    udpBlocks.set(rule, `AND,((NETWORK,UDP),(${selector})),REJECT`);
  }
  const generatedBlocks = new Set(udpBlocks.values());
  config.rules = outgoingRules.filter((rule) => !generatedBlocks.has(rule))
    .flatMap((rule) => udpBlocks.has(rule) ? [udpBlocks.get(rule), rule] : [rule]);
  config.proxies = [
    ...(config.proxies || []).filter((proxy) =>
      proxy.name !== outbound && proxy.name !== wifiCallingOutbound && proxy.name !== ntpOutbound),
    { name: outbound, type: "direct", "interface-name": usbInterface, "ip-version": "ipv4", udp: false },
    { name: ntpOutbound, type: "direct", "interface-name": usbInterface, "ip-version": "ipv4", udp: true },
    ...(matchedProviders.has(wifiCallingProvider) ? [{
      name: wifiCallingOutbound, type: "direct", "interface-name": usbInterface, "ip-version": "ipv4", udp: true
    }] : [])
  ];

  if (config.dns?.enable) {
    const dnsOverHttps = `https://1.1.1.1/dns-query#${usbInterface}`;
    const policy = { ...config.dns["nameserver-policy"] };
    for (const host of routedHosts) policy[host] = dnsOverHttps;
    for (const domain of routedDomains) policy[`+.${domain}`] = dnsOverHttps;
    policy[`rule-set:${claudeTelemetry}`] = dnsOverHttps;
    for (const provider of matchedProviders) {
      const behavior = providers[provider]?.behavior;
      if (provider !== "ai_ip" && (behavior === "classical" || behavior === "domain")) {
        policy[`rule-set:${provider}`] = dnsOverHttps;
      }
    }
    config.dns["nameserver-policy"] = policy;
  }

  if (easyTierRelay) {
    const { listen, network, port, username, password } = easyTierRelay;
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(listen) || listen === "0.0.0.0" ||
        !Number.isInteger(port) || port < 1 || port > 65535 || !network || !username || !password) {
      throw new Error("EasyTier relay requires an explicit IPv4 address, port, source CIDR and credentials");
    }
    const name = "easytier-relay";
    const relayRule = `SUB-RULE,(IN-NAME,${name}),${name}`;
    config.listeners = [
      ...(config.listeners || []).filter((listener) => listener.name !== name),
      { name, type: "mixed", listen, port, udp: false, users: [{ username, password }] }
    ];
    (config["sub-rules"] ||= {})[name] = [
      `NOT,((SRC-IP-CIDR,${network})),REJECT`,
      ...scopedDomainRules,
      ...claudeIpRules,
      ...Array.from(matchedProviders)
        .filter((provider) => aiProviders.has(provider))
        .map((provider) => `RULE-SET,${provider},${outbound},no-resolve`),
      "MATCH,REJECT"
    ];
    config.rules = [relayRule, ...config.rules.filter((rule) => rule !== relayRule)];
  }

  return config;
}
