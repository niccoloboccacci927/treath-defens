require("dotenv").config();

const {
  Client,
  GatewayIntentBits,
  Partials,
  PermissionsBitField,
  AuditLogEvent
} = require("discord.js");

// ======================================================
// 🛡️ THREAT GUARD - BOT 1
// Real-Time Protection System
// ======================================================

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildModeration
  ],
  partials: [Partials.Channel]
});

// ======================================================
// ⚙️ CONFIG
// ======================================================

const CONFIG = {
  RAID_WINDOW_MS: 15000,
  RAID_THRESHOLD: 5,

  MAX_RISK: 100,

  MONITOR_RISK: 30,
  TIMEOUT_RISK: 60,
  BAN_RISK: 100,

  ACCOUNT_MIN_AGE_MS: 1000 * 60 * 60 * 24 * 3, // 3 giorni

  ENABLE_AUTO_BAN: false, // ⚠️ FALSE PER SICUREZZA TEST

  CAPTCHA_ROLE_NAME: "Verified",

  DANGEROUS_KEYWORDS: [
    "nuke",
    "raid",
    "massban",
    "crash",
    "spamall",
    "adminall",
    "destroy",
    "token grab",
    "free nitro scam"
  ],

  BAD_LINK_PATTERNS: [
    "discord.gg/",
    "bit.ly",
    "tinyurl",
    "grabify",
    "iplogger",
    "nitro-free",
    "steamcommunity.ru"
  ]
};

// ======================================================
// 🧠 MEMORY SYSTEM
// ======================================================

const userRisk = new Map();
const monitoredUsers = new Map();
const joinCache = [];
const messageCache = new Map();

// ======================================================
// 🧠 UTILITIES
// ======================================================

function addRisk(userId, amount, reason = "unknown") {
  const current = userRisk.get(userId) || 0;
  const updated = current + amount;

  userRisk.set(userId, updated);

  console.log(
    `⚠️ RISK UPDATE | ${userId} | +${amount} | ${reason} | TOTAL: ${updated}`
  );

  return updated;
}

function normalize(text) {
  return text.toLowerCase().replace(/\s+/g, "");
}

function containsDangerousKeyword(content) {
  const normalized = normalize(content);

  return CONFIG.DANGEROUS_KEYWORDS.some((keyword) =>
    normalized.includes(keyword)
  );
}

function containsBadLink(content) {
  return CONFIG.BAD_LINK_PATTERNS.some((pattern) =>
    content.toLowerCase().includes(pattern)
  );
}

function monitorUser(userId, reason) {
  monitoredUsers.set(userId, {
    since: Date.now(),
    reason
  });

  console.log(`👁️ USER MONITORED | ${userId} | ${reason}`);
}

async function safeDelete(message) {
  try {
    await message.delete();
  } catch {}
}

async function timeoutMember(member, minutes = 10) {
  try {
    await member.timeout(minutes * 60 * 1000);
  } catch {}
}

async function banMember(member, reason) {
  if (!CONFIG.ENABLE_AUTO_BAN) {
    console.log("⛔ AUTO BAN DISABLED");
    return;
  }

  try {
    await member.ban({ reason });
  } catch {}
}

// ======================================================
// 🚀 READY
// ======================================================

client.on("ready", () => {
  console.log(`🛡️ Threat Guard online as ${client.user.tag}`);
});

// ======================================================
// 🚨 RAID DETECTION
// ======================================================

client.on("guildMemberAdd", async (member) => {
  const now = Date.now();

  joinCache.push({
    id: member.id,
    time: now
  });

  while (
    joinCache.length &&
    now - joinCache[0].time > CONFIG.RAID_WINDOW_MS
  ) {
    joinCache.shift();
  }

  // ==================================================
  // 🚨 ACCOUNT AGE CHECK
  // ==================================================

  const accountAge = now - member.user.createdTimestamp;

  if (accountAge < CONFIG.ACCOUNT_MIN_AGE_MS) {
    addRisk(member.id, 25, "new_account");
    monitorUser(member.id, "new_account");
  }

  // ==================================================
  // 🚨 RAID DETECTED
  // ==================================================

  if (joinCache.length >= CONFIG.RAID_THRESHOLD) {
    console.log("🚨 RAID DETECTED");

    addRisk(member.id, 30, "raid_join");
    monitorUser(member.id, "raid_detection");

    try {
      await member.guild.systemChannel?.send(
        "🚨 Possible raid detected. Protection mode enabled."
      );
    } catch {}
  }

  // ==================================================
  // 🤖 BOT JOIN CHECK
  // ==================================================

  if (member.user.bot) {
    console.log(`🤖 BOT JOINED | ${member.user.tag}`);

    addRisk(member.id, 20, "bot_join");

    monitorUser(member.id, "bot_join");
  }
});

// ======================================================
// 💬 MESSAGE ANALYSIS
// ======================================================

client.on("messageCreate", async (message) => {
  if (!message.guild) return;
  if (message.author.bot) return;

  const userId = message.author.id;
  const content = message.content.toLowerCase();

  let risk = userRisk.get(userId) || 0;

  // ==================================================
  // 📦 MESSAGE SPAM CACHE
  // ==================================================

  if (!messageCache.has(userId)) {
    messageCache.set(userId, []);
  }

  const userMessages = messageCache.get(userId);

  userMessages.push(Date.now());

  while (
    userMessages.length &&
    Date.now() - userMessages[0] > 5000
  ) {
    userMessages.shift();
  }

  // ==================================================
  // 🚨 MESSAGE FLOOD
  // ==================================================

  if (userMessages.length >= 6) {
    risk = addRisk(userId, 20, "message_flood");

    await safeDelete(message);

    monitorUser(userId, "message_flood");
  }

  // ==================================================
  // 🔗 MALICIOUS LINKS
  // ==================================================

  if (containsBadLink(content)) {
    risk = addRisk(userId, 35, "malicious_link");

    await safeDelete(message);

    monitorUser(userId, "malicious_link");
  }

  // ==================================================
  // ⚠️ DANGEROUS COMMANDS
  // ==================================================

  if (containsDangerousKeyword(content)) {
    risk = addRisk(userId, 25, "dangerous_command");

    await safeDelete(message);

    monitorUser(userId, "dangerous_command");

    console.log(
      `⚠️ Dangerous command blocked from ${message.author.tag}`
    );
  }

  // ==================================================
  // 📢 EVERYONE / HERE SPAM
  // ==================================================

  if (
    content.includes("@everyone") ||
    content.includes("@here")
  ) {
    risk = addRisk(userId, 15, "mention_spam");

    await safeDelete(message);
  }

  // ==================================================
  // 🧠 LONG MESSAGE CHECK
  // ==================================================

  if (content.length > 400) {
    risk = addRisk(userId, 5, "long_message");
  }

  // ==================================================
  // 🚨 ESCALATION
  // ==================================================

  if (risk >= CONFIG.MONITOR_RISK) {
    monitorUser(userId, "high_risk");
  }

  if (risk >= CONFIG.TIMEOUT_RISK) {
    console.log(`⏳ USER TIMEOUT | ${message.author.tag}`);

    await timeoutMember(message.member, 10);
  }

  if (risk >= CONFIG.BAN_RISK) {
    console.log(`⛔ USER BAN | ${message.author.tag}`);

    await banMember(
      message.member,
      "Threat Guard Security System"
    );
  }
});

// ======================================================
// 🚨 ANTI-NUKE BASIC
// ======================================================

client.on("channelDelete", async (channel) => {
  try {
    const logs = await channel.guild.fetchAuditLogs({
      type: AuditLogEvent.ChannelDelete,
      limit: 1
    });

    const entry = logs.entries.first();

    if (!entry) return;

    const executor = entry.executor;

    if (!executor) return;

    const risk = addRisk(
      executor.id,
      40,
      "channel_delete"
    );

    monitorUser(executor.id, "channel_delete");

    console.log(
      `🚨 CHANNEL DELETE DETECTED | ${executor.tag}`
    );

    if (risk >= CONFIG.TIMEOUT_RISK) {
      const member =
        await channel.guild.members.fetch(executor.id);

      await timeoutMember(member, 30);
    }
  } catch (err) {
    console.log("Audit log error:", err.message);
  }
});

// ======================================================
// 🔄 CLEANUP LOOP
// ======================================================

setInterval(() => {
  const now = Date.now();

  for (const [userId, data] of monitoredUsers.entries()) {
    const duration = now - data.since;

    // 20 giorni
    if (duration > 1000 * 60 * 60 * 24 * 20) {
      monitoredUsers.delete(userId);

      console.log(`✅ Monitoring expired for ${userId}`);
    }
  }
}, 60 * 1000);

// ======================================================
// 🔐 LOGIN
// ======================================================

client.login(process.env.TOKEN);