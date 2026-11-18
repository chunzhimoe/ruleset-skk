// Clash Party subscription override for a CT UK USB connection on macOS.
function main(config) {
  if (!Array.isArray(config.rules)) return config;

  const outbound = "CT-UK · USB 4G";
  const usbInterface = "feth50";
  const claudeProcess = "PROCESS-PATH-REGEX,(?i)(^|/)Claude[.]app/Contents/";
  const claudeLoopback = `AND,((${claudeProcess}),(OR,((IP-CIDR,127.0.0.0/8,no-resolve),(IP-CIDR6,::1/128,no-resolve)))),DIRECT`;
  const claudeDomains = ["claude.ai", "claude.com", "claudeusercontent.com", "anthropic.com"];
  const customHost = "na.gateway.spring.citi.com";
  const customRule = `DOMAIN,${customHost},`;
  const leadingRules = [
    claudeLoopback,
    `${claudeProcess},${outbound}`,
    customRule + outbound,
    ...claudeDomains.map((domain) => `DOMAIN-SUFFIX,${domain},${outbound}`)
  ];
  const generatedRules = new Set(leadingRules);
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
  const existingRules = config.rules.filter((rule) =>
    typeof rule !== "string" || (!rule.startsWith(customRule) && !generatedRules.has(rule))
  );
  const rules = existingRules.map((rule) => {
    if (typeof rule !== "string") return rule;
    const parts = rule.split(",");
    const provider = parts[1]?.trim();
    if (parts.length < 3 || parts[0].trim() !== "RULE-SET" ||
        !aiProviders.has(provider)) return rule;
    matchedProviders.add(provider);
    parts[2] = outbound;
    return parts.join(",");
  });
  // Preserve the subscription's specific rules ahead of the new AI domain rules.
  const broadRule = /^(?:RULE-SET,(?:lancidr|streamingip|google|apple|microsoft|global|domestic|direct),|GEOIP,|MATCH,)/;
  const domainBoundary = rules.findIndex((rule) => broadRule.test(rule));
  const domainRules = ["ai_non_ip", "apple_intelligence_non_ip"]
    .filter((name) => !matchedProviders.has(name))
    .map((name) => `RULE-SET,${name},${outbound}`);
  rules.splice(domainBoundary < 0 ? rules.length : domainBoundary, 0, ...domainRules);
  if (!matchedProviders.has("ai_ip")) {
    const ipBoundary = rules.findIndex((rule) => /^(GEOIP|MATCH),/.test(rule));
    rules.splice(ipBoundary < 0 ? rules.length : ipBoundary, 0, `RULE-SET,ai_ip,${outbound}`);
  }

  const providers = (config["rule-providers"] ||= {});
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
    if (target !== outbound || !/^(DOMAIN|DOMAIN-SUFFIX|PROCESS-PATH-REGEX|RULE-SET)$/.test(type)) continue;
    const selector = [type, value, ...flags].join(",");
    udpBlocks.set(rule, `AND,((NETWORK,UDP),(${selector})),REJECT`);
  }
  const generatedBlocks = new Set(udpBlocks.values());
  config.rules = outgoingRules.filter((rule) => !generatedBlocks.has(rule))
    .flatMap((rule) => udpBlocks.has(rule) ? [udpBlocks.get(rule), rule] : [rule]);
  config.proxies = [
    ...(config.proxies || []).filter((proxy) => proxy.name !== outbound),
    { name: outbound, type: "direct", "interface-name": usbInterface, "ip-version": "ipv4", udp: false }
  ];

  if (config.dns?.enable) {
    const dnsOverHttps = `https://1.1.1.1/dns-query#${usbInterface}`;
    const policy = { ...config.dns["nameserver-policy"] };
    policy[customHost] = dnsOverHttps;
    for (const domain of claudeDomains) policy[`+.${domain}`] = dnsOverHttps;
    for (const provider of matchedProviders) {
      const behavior = providers[provider]?.behavior;
      if (provider !== "ai_ip" && (behavior === "classical" || behavior === "domain")) {
        policy[`rule-set:${provider}`] = dnsOverHttps;
      }
    }
    config.dns["nameserver-policy"] = policy;
  }

  return config;
}
