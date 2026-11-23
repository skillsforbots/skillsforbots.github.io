/*
  Skills for Bots SKILL.md checker.
  Runs only in your browser. This file makes no network requests:
  no fetch, no XMLHttpRequest, no beacons, no storage. The page also sets a
  Content-Security-Policy with connect-src 'none' so the browser blocks any request.
  It is a helper, not a guarantee. It reads text patterns; it cannot prove a skill is safe.
*/
(function (root) {
  "use strict";

  var NAME_MAX = 64;
  var DESC_MAX = 1024;
  var LINE_SOFT_MAX = 500;

  // Words that show a risky action is fenced off by a rule (negation, approval, waiting).
  var GUARD_RE = /\b(never|not|no|don't|do not|doesn't|does not|without (?:the )?(?:owner|user|my|your|explicit)?\s*(?:explicit )?(?:approval|permission|ok|consent)|approval|approve[sd]?|permission|ask(?:s|ing)? (?:first|before|me|the owner|the user)|wait(?:s)? for|stop(?:s)? (?:and|before)|draft|confirm|only (?:after|when|if)|even if|nothing|to (?:the owner|me|you|\[OWNER[A-Z ]*\])|treat\b.*\bas information)\b/i;

  var RISKY_ACTIONS = [
    { id: "send", label: "Sends email or messages", re: /\b(send(?:s|ing)?|e-?mail(?:s|ing)?|text(?:s|ing)? (?:them|people|contacts)|post(?:s|ing)? (?:to|on)|reply(?:ing)? to|message (?:people|contacts|them))\b/i },
    { id: "spend", label: "Spends money", re: /\b(spend(?:s|ing)?|purchas(?:e|es|ed|ing)|buy(?:s|ing)?|pay(?:s|ing)?|checkout|check out|order(?:s|ing)? (?:food|it|items|online)|subscrib(?:e|es|ing)|tip(?:s|ping)? (?:the |a )?(?:driver|server|courier|\$)|transfer(?:s|ring)? (?:money|funds))\b/i },
    { id: "payment", label: "Payment details", re: /\b(payment|credit card|card number|debit card|bank account|routing number|cvv|wallet)\b/i },
    { id: "delete", label: "Deletes things", re: /\b(delet(?:e|es|ed|ing)|remov(?:e|es|ing) (?:files?|emails?|data|records?)|wipe|erase|rm -rf|drop table|empty (?:the )?trash)\b/i },
    { id: "password", label: "Passwords", re: /\b(password|passcode|passphrase|2fa code|one-time code|otp)\b/i },
    { id: "apikey", label: "API keys and tokens", re: /\b(api[ _-]?keys?|access tokens?|secret keys?|private keys?|bearer tokens?|client secret)\b/i }
  ];

  // Text that tries to steer an AI bot against its owner.
  var INJECTION_PATTERNS = [
    /\bignore (?:all |any |the )?(?:previous|prior|above|earlier|other|your) (?:instructions|rules|prompts?|messages?)\b/i,
    /\bdisregard (?:all |any |the )?(?:previous|prior|above|earlier|your) (?:instructions|rules)\b/i,
    /\bforget (?:all |your )?(?:previous |prior )?(?:instructions|rules)\b/i,
    /\b(?:do not|don't|never) (?:tell|inform|show|mention (?:this |it )?to|alert|let) (?:the )?(?:user|owner|human)(?: know)?\b(?! to\b)/i,
    /\bwithout (?:telling|informing|asking) (?:the )?(?:user|owner|human)\b/i,
    /\b(?:hide|conceal) (?:this|it|these instructions) from (?:the )?(?:user|owner|human)\b/i,
    /\bsecretly\b/i,
    /\byou are now (?:in )?(?:developer|dan|jailbreak|unrestricted)\b/i,
    /\bnote to (?:the )?(?:ai|llm|assistant|model|bot)\b/i,
    /\bif you are an? (?:ai|llm|language model|assistant|bot)\b/i
  ];

  // Lines that quote an injection phrase in order to defend against it.
  var DEFENSIVE_RE = /\b(treat|as information|never follow|do not follow|don't follow|even if|if (?:outside |the )?(?:content|a page|an email|a document|text)|tell (?:the )?(?:owner|user) and wait|ignore orders found|ignore instructions (?:hidden |found )?in)\b/i;

  var SECRET_PATTERNS = [
    { label: "Something that looks like an OpenAI-style key (sk-...)", re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
    { label: "Something that looks like an AWS access key", re: /\bAKIA[0-9A-Z]{16}\b/ },
    { label: "Something that looks like a GitHub token", re: /\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b/ },
    { label: "Something that looks like a Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
    { label: "A private key block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
    { label: "A password written out", re: /\b(?:password|passwd|pwd)\s*[:=]\s*\S{4,}/i }
  ];

  var HIDDEN_CHARS = [
    { label: "zero-width characters", re: /[\u200B\u200C\u200D\u2060\uFEFF]/g },
    { label: "text-direction control characters", re: /[\u202A-\u202E\u2066-\u2069]/g },
    { label: "invisible Unicode tag characters", re: /[\uDB40][\uDC00-\uDC7F]/g }
  ];

  var SHORTENERS = /^(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|tiny\.cc)$/i;

  function result(status, title, detail) {
    return { status: status, title: title, detail: detail || "" };
  }

  function splitLines(text) {
    return text.replace(/\r\n?/g, "\n").split("\n");
  }

  // Minimal YAML frontmatter reader: top-level "key: value", plus folded (>, >-) and literal (|, |-) blocks.
  function parseFrontmatter(text) {
    var lines = splitLines(text);
    var start = 0;
    while (start < lines.length && lines[start].trim() === "" ) start++;
    if (start >= lines.length || lines[start].trim() !== "---") {
      return { present: false, leadingBlank: false };
    }
    var end = -1;
    for (var i = start + 1; i < lines.length; i++) {
      if (lines[i].trim() === "---") { end = i; break; }
    }
    if (end === -1) return { present: false, unclosed: true };
    var fields = {};
    var keys = [];
    var j = start + 1;
    while (j < end) {
      var line = lines[j];
      var m = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
      if (!m) { j++; continue; }
      var key = m[1];
      var val = m[2];
      keys.push(key);
      if (/^[>|][+-]?\s*$/.test(val)) {
        var folded = val.charAt(0) === ">";
        var parts = [];
        j++;
        while (j < end && (/^\s+\S/.test(lines[j]) || lines[j].trim() === "")) {
          parts.push(lines[j].trim());
          j++;
        }
        fields[key] = folded ? parts.join(" ").replace(/\s+/g, " ").trim() : parts.join("\n").trim();
        continue;
      }
      // Nested map (e.g. metadata:) or plain multi-line scalar
      var cont = [];
      j++;
      while (j < end && /^\s+\S/.test(lines[j])) { cont.push(lines[j].trim()); j++; }
      if (val === "" && cont.length) {
        fields[key] = cont.join("\n");
      } else {
        var full = [val].concat(cont).join(" ").trim();
        full = full.replace(/^(["'])([\s\S]*)\1$/, "$2");
        fields[key] = full;
      }
    }
    return {
      present: true,
      leadingBlank: start > 0,
      fields: fields,
      keys: keys,
      body: lines.slice(end + 1).join("\n"),
      bodyStartLine: end + 2
    };
  }

  function checkName(name) {
    var problems = [];
    if (name.length < 1 || name.length > NAME_MAX) problems.push("it must be 1 to " + NAME_MAX + " characters (yours is " + name.length + ")");
    if (/[^a-z0-9-]/.test(name)) problems.push("it may only use lowercase letters a-z, numbers, and hyphens");
    if (/^-|-$/.test(name)) problems.push("it can't start or end with a hyphen");
    if (/--/.test(name)) problems.push("it can't contain two hyphens in a row");
    return problems;
  }

  function lineNumberOf(lines, idx) { return idx + 1; }

  function findLines(lines, re, offset) {
    var hits = [];
    for (var i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) hits.push({ n: i + 1 + (offset || 0), text: lines[i] });
    }
    return hits;
  }

  function fmtLines(hits, max) {
    max = max || 5;
    var shown = hits.slice(0, max).map(function (h) { return h.n; }).join(", ");
    return "line" + (hits.length > 1 ? "s " : " ") + shown + (hits.length > max ? " and " + (hits.length - max) + " more" : "");
  }

  function check(text) {
    var out = [];
    text = String(text || "");
    if (text.trim() === "") {
      return [result("warn", "Nothing to check", "Paste the full text of a SKILL.md file, starting with the --- line.")];
    }
    var allLines = splitLines(text);

    // 1. Frontmatter
    var fm = parseFrontmatter(text);
    if (!fm.present) {
      out.push(result("warn", "Frontmatter missing",
        fm.unclosed ? "The file opens with --- but never closes it. Add a second --- line after the description."
                    : "A SKILL.md should start with a --- line, then name: and description:, then another --- line."));
    } else {
      out.push(result("pass", "Frontmatter found", "The file opens and closes a --- frontmatter block."));
      if (fm.leadingBlank) out.push(result("warn", "Blank lines before the frontmatter", "Some tools expect --- on the very first line. Delete the empty lines above it."));
    }
    var fields = (fm && fm.fields) || {};
    var body = fm.present ? fm.body : text;
    var bodyOffset = fm.present ? fm.bodyStartLine - 1 : 0;
    var bodyLines = splitLines(body);

    // 2. name
    if (fm.present) {
      if (typeof fields.name !== "string" || fields.name === "") {
        out.push(result("warn", "name is missing", "Add a line like name: my-skill-name inside the frontmatter."));
      } else {
        var np = checkName(fields.name);
        if (np.length) out.push(result("warn", "name doesn't follow the format", "\"" + fields.name + "\": " + np.join("; ") + "."));
        else out.push(result("pass", "name looks right", "\"" + fields.name + "\" uses lowercase letters, numbers, and single hyphens. Make sure the skill's folder has the same name."));
      }

      // 3. description
      var d = fields.description;
      if (typeof d !== "string" || d === "") {
        out.push(result("warn", "description is missing", "Add description: with what the skill does and when to use it. Bots read this to decide when to load the skill."));
      } else if (d.length > DESC_MAX) {
        out.push(result("warn", "description is too long", "It is " + d.length + " characters. The limit is " + DESC_MAX + ". Move detail into the body."));
      } else {
        out.push(result("pass", "description length is fine", d.length + " of " + DESC_MAX + " characters."));
        if (d.length < 40) out.push(result("warn", "description is very short", "Say what the skill does and when a bot should use it, with the words a person would actually type."));
        if (!/\b(use (?:this|it|when|for|whenever)|when (?:the|a|you|someone)|whenever)\b/i.test(d)) {
          out.push(result("warn", "description doesn't say when to use it", "Add a \"Use when...\" phrase so the bot knows which requests should trigger the skill."));
        }
        if (/\[[A-Z][A-Z _-]*\]/.test(d)) out.push(result("warn", "description still has a [PLACEHOLDER]", "Fill it in before you add the skill. The description is the part a bot always sees."));
      }

      // Extra keys
      var known = { name: 1, description: 1, license: 1, compatibility: 1, metadata: 1, "allowed-tools": 1 };
      var extra = (fm.keys || []).filter(function (k) { return !known[k]; });
      var optional = (fm.keys || []).filter(function (k) { return k !== "name" && k !== "description" && known[k]; });
      if (extra.length) out.push(result("warn", "Frontmatter has non-standard fields", "Found: " + extra.join(", ") + ". Some tools ignore these and some may reject them. For the widest compatibility, keep to name and description."));
      if (optional.length) out.push(result("info", "Optional fields present", "Found: " + optional.join(", ") + ". These are in the open spec, but support varies by tool." + (optional.indexOf("allowed-tools") !== -1 ? " allowed-tools pre-approves tools in some apps, so read it carefully." : "")));
      if (fields.compatibility && fields.compatibility.length > 500) out.push(result("warn", "compatibility is too long", "The open spec caps it at 500 characters."));
    }

    // 4. Length
    var lineCount = allLines.length;
    if (lineCount > LINE_SOFT_MAX) {
      out.push(result("warn", "The file is long", lineCount + " lines. The open spec suggests keeping SKILL.md under " + LINE_SOFT_MAX + " lines and moving reference material into separate files."));
    } else if (bodyLines.join("").trim().length < 200) {
      out.push(result("warn", "The body is very short", "There isn't much for the bot to follow. Add steps, an example, and the rules it must keep."));
    } else {
      out.push(result("pass", "Length is reasonable", lineCount + " lines, " + text.length + " characters."));
    }

    // 5. Safety / approval section
    var headingRe = /^#{1,6}\s+.*\b(safety|approval|approvals|permission|permissions|rules|never|guardrails?|ask (?:first|before)|before (?:you|it) act|limits?|boundaries|(?:does not|doesn't|won't|will not|must not|should not|shouldn't) do|what not to do|don'ts)\b/i;
    var safetyHeads = findLines(bodyLines, headingRe, bodyOffset);
    if (safetyHeads.length) {
      out.push(result("pass", "Safety or approval section found", "Heading on " + fmtLines(safetyHeads) + ": \"" + safetyHeads[0].text.replace(/^#+\s*/, "") + "\"."));
    } else {
      out.push(result("warn", "No safety or approval section", "Add a heading such as \"## Ask before acting\" or \"## Never\" that says what the bot must not do without your OK, like sending, spending, or deleting."));
    }

    // 6. Disclaimer
    var disclaimerRe = /\b(provided as is|as-is|no warranty|without warranty|not (?:legal|financial|medical|tax|professional|investment) advice|not a (?:hard )?(?:technical )?(?:block|lock|guarantee)|no results (?:are )?(?:promised|guaranteed)|use at your own risk|you(?:'re| are) responsible for)\b/i;
    var disc = findLines(allLines, disclaimerRe, 0);
    if (disc.length) out.push(result("pass", "Disclaimer found", "On " + fmtLines(disc) + "."));
    else out.push(result("warn", "No disclaimer", "Add a short note that the skill is instructions to a bot, not a guarantee, and is provided as is."));

    // 7. Risky actions
    // Lines inside a safety/approval section (until the next heading of the same or higher level).
    var ruleLineNums = {};
    for (var bi = 0; bi < bodyLines.length; bi++) {
      var hm = /^(#{1,6})\s+/.exec(bodyLines[bi]);
      if (hm && headingRe.test(bodyLines[bi])) {
        var lvl = hm[1].length;
        for (var bj = bi + 1; bj < bodyLines.length; bj++) {
          var hm2 = /^(#{1,6})\s+/.exec(bodyLines[bj]);
          if (hm2 && hm2[1].length <= lvl) break;
          ruleLineNums[bj + 1 + bodyOffset] = true;
        }
      }
    }
    RISKY_ACTIONS.forEach(function (a) {
      var hits = findLines(bodyLines, a.re, bodyOffset);
      if (!hits.length) return;
      var ruled = hits.filter(function (h) { return ruleLineNums[h.n] && GUARD_RE.test(h.text); });
      var unguarded = hits.filter(function (h) { return !GUARD_RE.test(h.text); });
      if (ruled.length) {
        out.push(result("pass", a.label + ": covered by a rule",
          "Mentioned on " + fmtLines(hits) + ". Your safety section limits it on " + fmtLines(ruled) + ". Read that rule once more to be sure it says what you mean."));
      } else if (unguarded.length) {
        out.push(result("warn", a.label + " without a clear rule nearby",
          "Mentioned on " + fmtLines(unguarded) + " with no \"ask first\", \"never\", or approval wording on the same line, and no matching rule in a safety section. Check that the bot must get your OK first. Example: \"" + unguarded[0].text.trim().slice(0, 140) + "\""));
      } else {
        out.push(result("pass", a.label + ": guarded", "Mentioned on " + fmtLines(hits) + ", and each line carries a rule such as never, ask first, or approval."));
      }
    });

    // 8. Secrets pasted in
    SECRET_PATTERNS.forEach(function (s) {
      var hits = findLines(allLines, s.re, 0);
      if (hits.length) out.push(result("warn", "Possible secret in the file", s.label + " on " + fmtLines(hits) + ". Never put real keys or passwords in a skill. Remove it and change that key or password."));
    });

    // 9. Hidden text and instructions aimed at AI
    var hiddenFound = false;
    HIDDEN_CHARS.forEach(function (h) {
      var count = (text.match(h.re) || []).length;
      if (count) {
        hiddenFound = true;
        var hits = findLines(allLines, new RegExp(h.re.source), 0);
        out.push(result("warn", "Hidden characters: " + h.label, count + " found, on " + fmtLines(hits) + ". These can hide text from people while a bot still reads it. Delete them unless you know why they are there."));
      }
    });
    var commentHits = findLines(allLines, /<!--/, 0);
    if (commentHits.length) {
      hiddenFound = true;
      out.push(result("warn", "HTML comments", "On " + fmtLines(commentHits) + ". Comments don't show when Markdown is displayed, but a bot reads them. Read each one, or remove them."));
    }
    var injHits = [];
    allLines.forEach(function (line, i) {
      for (var p = 0; p < INJECTION_PATTERNS.length; p++) {
        if (INJECTION_PATTERNS[p].test(line) && !DEFENSIVE_RE.test(line)) { injHits.push({ n: i + 1, text: line }); break; }
      }
    });
    if (injHits.length) {
      out.push(result("warn", "Instructions that work against the owner", "On " + fmtLines(injHits) + ": wording like \"ignore previous instructions\", \"don't tell the user\", or \"secretly\". A trustworthy skill doesn't need these. Example: \"" + injHits[0].text.trim().slice(0, 140) + "\""));
    } else if (!hiddenFound) {
      out.push(result("pass", "No hidden text or override phrases found", "No zero-width or direction-control characters, no HTML comments, and no \"ignore previous instructions\" style wording."));
    } else {
      out.push(result("pass", "No override phrases found", "No \"ignore previous instructions\" style wording. See the hidden-character results above."));
    }

    // 10. Remote code
    var pipeHits = findLines(allLines, /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\biex\s*\(|Invoke-Expression|\beval\s*\(/i, 0);
    if (pipeHits.length) out.push(result("warn", "Downloads and runs code", "On " + fmtLines(pipeHits) + ". The bot would run code from the internet. Only keep this if you trust the source and have read the script."));

    // 11. External links
    var urlRe = /\bhttps?:\/\/[^\s<>()"'`\]]+/gi;
    var urls = text.match(urlRe) || [];
    if (!urls.length) {
      out.push(result("pass", "No external links", "The skill doesn't point the bot at any outside web address."));
    } else {
      var hosts = {};
      var insecure = [];
      var short = [];
      var ipHosts = [];
      urls.forEach(function (u) {
        var m = /^(https?):\/\/([^\/:?#]+)/i.exec(u);
        if (!m) return;
        var host = m[2].toLowerCase();
        hosts[host] = (hosts[host] || 0) + 1;
        if (m[1].toLowerCase() === "http") insecure.push(u);
        if (SHORTENERS.test(host)) short.push(u);
        if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) ipHosts.push(u);
      });
      var hostList = Object.keys(hosts).sort();
      out.push(result("info", "External links: " + urls.length, "Domains: " + hostList.join(", ") + ". A bot may open these and read what they say. Make sure you trust each one."));
      if (insecure.length) out.push(result("warn", "Links without https", insecure.slice(0, 3).join(", ") + (insecure.length > 3 ? " and more" : "") + "."));
      if (short.length) out.push(result("warn", "Shortened links", short.slice(0, 3).join(", ") + ". You can't see where these go. Replace them with the full address."));
      if (ipHosts.length) out.push(result("warn", "Links to raw IP addresses", ipHosts.slice(0, 3).join(", ") + "."));
    }

    // 12. Leftover placeholders
    var ph = findLines(bodyLines, /\[[A-Z][A-Z0-9 _\/-]{2,}\]/, bodyOffset);
    if (ph.length) out.push(result("info", "Placeholders to fill", "[BRACKET] placeholders on " + fmtLines(ph) + ". That's normal for a template. Fill them before you add the skill to a bot."));

    return out;
  }

  function summarize(results) {
    var s = { pass: 0, warn: 0, info: 0 };
    results.forEach(function (r) { s[r.status] = (s[r.status] || 0) + 1; });
    return s;
  }

  var api = { check: check, summarize: summarize, parseFrontmatter: parseFrontmatter, checkName: checkName };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.SkillMdChecker = api;

  // Browser UI. Uses textContent only, so pasted text is never run as HTML.
  if (typeof document !== "undefined") {
    var ready = function () {
      var input = document.getElementById("skill-input");
      var btn = document.getElementById("check-btn");
      var clearBtn = document.getElementById("clear-btn");
      var good = document.getElementById("load-good");
      var risky = document.getElementById("load-risky");
      var list = document.getElementById("results");
      var summary = document.getElementById("summary");
      if (!input || !btn || !list) return;
      var labels = { pass: "Pass", warn: "Warn", info: "Note" };
      var run = function () {
        var res = check(input.value);
        var s = summarize(res);
        while (list.firstChild) list.removeChild(list.firstChild);
        res.forEach(function (r) {
          var li = document.createElement("li");
          li.className = "r r-" + r.status;
          var tag = document.createElement("span");
          tag.className = "tag";
          tag.textContent = labels[r.status] || r.status;
          var t = document.createElement("strong");
          t.textContent = " " + r.title;
          var p = document.createElement("span");
          p.className = "detail";
          p.textContent = r.detail;
          li.appendChild(tag); li.appendChild(t); li.appendChild(p);
          list.appendChild(li);
        });
        summary.textContent = s.pass + " pass, " + s.warn + " warn, " + s.info + " note" + (s.info === 1 ? "" : "s") +
          ". A clean result means none of these patterns turned up. It does not mean the skill is safe.";
        summary.hidden = false;
        summary.focus();
      };
      btn.addEventListener("click", run);
      if (clearBtn) clearBtn.addEventListener("click", function () {
        input.value = ""; while (list.firstChild) list.removeChild(list.firstChild); summary.hidden = true; input.focus();
      });
      var loadFrom = function (id) {
        var el = document.getElementById(id);
        if (el) { input.value = el.textContent.replace(/^\n/, ""); run(); }
      };
      if (good) good.addEventListener("click", function () { loadFrom("sample-good"); });
      if (risky) risky.addEventListener("click", function () { loadFrom("sample-risky"); });
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready);
    else ready();
  }
})(typeof window !== "undefined" ? window : this);
