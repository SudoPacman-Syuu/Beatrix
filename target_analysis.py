#!/usr/bin/env python3
"""
BEATRIX Target Analysis - Finding High-Value Bounty Programs
Focus: Good payouts, responsive programs, OWASP Top 10 opportunities
"""


# Based on HackerOne data and reputation research
HIGH_VALUE_TARGETS = {
    "tier_1_high_payout_responsive": [
        {
            "name": "Shopify",
            "url": "hackerone.com/shopify",
            "min_bounty": "$500",
            "max_bounty": "$200,000",
            "reputation": "EXCELLENT - Fast response, fair payouts",
            "scope": "Wide - multiple apps, APIs, subdomains",
            "owasp_opportunities": ["IDOR", "SSRF", "Injection", "Auth Bypass"],
            "notes": "Complex ecosystem, many entry points"
        },
        {
            "name": "Coinbase",
            "url": "hackerone.com/coinbase",
            "min_bounty": "$200",
            "max_bounty": "$1,000,000+",
            "reputation": "EXCELLENT - Crypto = high stakes = high payouts",
            "scope": "Exchange, wallets, APIs",
            "owasp_opportunities": ["Auth Bypass", "IDOR", "Race Conditions"],
            "notes": "Financial impact = premium payouts"
        },
        {
            "name": "GitLab",
            "url": "hackerone.com/gitlab",
            "min_bounty": "$100",
            "max_bounty": "$35,000",
            "reputation": "EXCELLENT - Very responsive, fair",
            "scope": "Self-hosted + SaaS, CI/CD",
            "owasp_opportunities": ["SSRF", "RCE via CI", "IDOR", "Auth"],
            "notes": "Open source = code review possible"
        },
        {
            "name": "Uber",
            "url": "hackerone.com/uber",
            "min_bounty": "$500",
            "max_bounty": "$50,000+",
            "reputation": "GOOD - Large attack surface",
            "scope": "Driver/rider apps, APIs, web",
            "owasp_opportunities": ["IDOR", "Auth", "API abuse"],
            "notes": "Massive user base = high impact"
        }
    ],
    "tier_2_newer_programs_less_hunted": [
        {
            "name": "Vercel Open Source",
            "url": "hackerone.com/vercel-open-source",
            "launched": "02/2026",
            "min_bounty": "$50",
            "reputation": "NEW - Less competition",
            "scope": "Open source projects",
            "owasp_opportunities": ["Injection", "SSRF", "Misconfig"],
            "notes": "BRAND NEW - likely has low-hanging fruit"
        },
        {
            "name": "Anduril Industries",
            "url": "hackerone.com/anduril_industries",
            "launched": "01/2026",
            "min_bounty": "$50",
            "reputation": "NEW - Defense tech = high value",
            "scope": "Defense applications",
            "owasp_opportunities": ["Auth", "IDOR", "Data exposure"],
            "notes": "Defense contractor - sensitive data"
        },
        {
            "name": "DoorDash",
            "url": "hackerone.com/doordash",
            "launched": "10/2025",
            "min_bounty": "$50",
            "reputation": "GOOD - Recently relaunched",
            "scope": "Consumer/driver apps, APIs",
            "owasp_opportunities": ["IDOR", "Auth", "API abuse"],
            "notes": "Food delivery = PII exposure opportunities"
        },
        {
            "name": "Notion Labs",
            "url": "hackerone.com/notion",
            "launched": "11/2025",
            "min_bounty": "$50",
            "reputation": "GOOD - Popular productivity tool",
            "scope": "Web app, API, integrations",
            "owasp_opportunities": ["SSRF", "XSS", "Auth", "IDOR"],
            "notes": "Lots of user data, collaboration features"
        },
        {
            "name": "Robinhood Markets Bounty",
            "url": "hackerone.com/robinhood",
            "launched": "10/2025",
            "min_bounty": "$50",
            "avg_bounty": "$966-$1k",
            "reputation": "GOOD - Financial = high payouts",
            "scope": "Trading platform, APIs",
            "owasp_opportunities": ["Auth", "IDOR", "Race conditions"],
            "notes": "Finance + crypto = premium payouts"
        }
    ],
    "tier_3_consistent_payers_wide_scope": [
        {
            "name": "Stripe",
            "url": "hackerone.com/stripe",
            "min_bounty": "$100",
            "reputation": "EXCELLENT - Consistent, fair",
            "scope": "Payment APIs, Dashboard, SDKs",
            "owasp_opportunities": ["Auth", "SSRF", "Injection"],
            "notes": "Payments = critical bugs = high payouts"
        },
        {
            "name": "Slack",
            "url": "hackerone.com/slack",
            "min_bounty": "$250",
            "reputation": "EXCELLENT - $12M+ paid out",
            "scope": "Web, desktop, mobile, APIs",
            "owasp_opportunities": ["XSS", "SSRF", "Auth", "IDOR"],
            "notes": "Enterprise = high impact"
        },
        {
            "name": "Netflix",
            "url": "hackerone.com/netflix",
            "min_bounty": "$50",
            "reputation": "GOOD - Large scope",
            "scope": "Streaming, APIs, CDN",
            "owasp_opportunities": ["Auth", "IDOR", "Injection"],
            "notes": "250M+ users = massive impact"
        },
        {
            "name": "GitHub",
            "url": "hackerone.com/github",
            "min_bounty": "$617",
            "max_bounty": "$30,000+",
            "reputation": "EXCELLENT - Microsoft backing",
            "scope": "Web, API, Actions, Codespaces",
            "owasp_opportunities": ["SSRF", "Auth", "Injection", "RCE"],
            "notes": "Developer platform = technical vulns"
        }
    ]
}

# Quick wins - OWASP Top 10 scanner targets
QUICK_SCAN_TARGETS = [
    # Open redirects - often overlooked
    {"type": "redirect", "targets": [
        "https://www.doordash.com",
        "https://www.notion.so",
        "https://dashboard.stripe.com",
        "https://app.slack.com"
    ]},
    # CORS misconfigurations
    {"type": "cors", "targets": [
        "https://api.doordash.com",
        "https://api.notion.so",
        "https://api.stripe.com",
        "https://api.slack.com"
    ]},
    # Security headers
    {"type": "headers", "targets": [
        "https://www.doordash.com",
        "https://www.notion.so",
        "https://www.robinhood.com",
        "https://vercel.com"
    ]},
    # SSRF potential endpoints
    {"type": "ssrf", "targets": [
        "webhook endpoints",
        "URL preview/unfurl features",
        "Image upload/import from URL",
        "PDF generators",
        "Export features"
    ]}
]

print("=" * 70)
print("🎯 BEATRIX TARGET ANALYSIS - HIGH-VALUE BUG BOUNTY PROGRAMS")
print("=" * 70)

print("\n📊 TIER 1 - HIGH PAYOUT, RESPONSIVE PROGRAMS")
print("-" * 50)
for target in HIGH_VALUE_TARGETS["tier_1_high_payout_responsive"]:
    print(f"\n🔥 {target['name']}")
    print(f"   URL: {target['url']}")
    print(f"   Min Bounty: {target['min_bounty']}")
    print(f"   Max Bounty: {target.get('max_bounty', 'N/A')}")
    print(f"   Reputation: {target['reputation']}")
    print(f"   OWASP Opportunities: {', '.join(target['owasp_opportunities'])}")
    print(f"   Notes: {target['notes']}")

print("\n\n📊 TIER 2 - NEWER PROGRAMS (LESS COMPETITION)")
print("-" * 50)
for target in HIGH_VALUE_TARGETS["tier_2_newer_programs_less_hunted"]:
    print(f"\n🆕 {target['name']}")
    print(f"   URL: {target['url']}")
    if 'launched' in target:
        print(f"   Launched: {target['launched']}")
    print(f"   Min Bounty: {target['min_bounty']}")
    print(f"   Reputation: {target['reputation']}")
    print(f"   OWASP Opportunities: {', '.join(target['owasp_opportunities'])}")
    print(f"   Notes: {target['notes']}")

print("\n\n📊 TIER 3 - CONSISTENT PAYERS, WIDE SCOPE")
print("-" * 50)
for target in HIGH_VALUE_TARGETS["tier_3_consistent_payers_wide_scope"]:
    print(f"\n💰 {target['name']}")
    print(f"   URL: {target['url']}")
    print(f"   Min Bounty: {target['min_bounty']}")
    print(f"   Max Bounty: {target.get('max_bounty', 'N/A')}")
    print(f"   Reputation: {target['reputation']}")
    print(f"   OWASP Opportunities: {', '.join(target['owasp_opportunities'])}")
    print(f"   Notes: {target['notes']}")

print("\n\n" + "=" * 70)
print("🚀 RECOMMENDED ATTACK STRATEGY")
print("=" * 70)

strategy = """
1. START WITH NEWER PROGRAMS (Less competition):
   - Vercel Open Source (BRAND NEW - Feb 2026)
   - DoorDash (Recently relaunched)
   - Notion (Nov 2025)

2. LOW-HANGING FRUIT CHECKLIST:
   ✓ Security Headers (X-Frame-Options, CSP, etc.)
   ✓ CORS Misconfigurations
   ✓ Open Redirects
   ✓ Information Disclosure (.git, .env, backup files)
   ✓ Subdomain Takeover

3. MEDIUM EFFORT, HIGH REWARD:
   ✓ IDOR on API endpoints
   ✓ Auth bypass (password reset, email verification)
   ✓ Rate limiting issues
   ✓ GraphQL introspection + mutations testing

4. HIGH EFFORT, PREMIUM PAYOUTS:
   ✓ SSRF (especially in webhook/URL features)
   ✓ SQL Injection
   ✓ RCE (command injection, template injection)
   ✓ Business logic flaws

5. PARALLEL SCANNING APPROACH:
   Terminal 1: Subdomain enumeration (subfinder, amass)
   Terminal 2: Port scanning (nmap)
   Terminal 3: Directory bruteforce (feroxbuster)
   Terminal 4: Vulnerability scanning (nuclei)
"""
print(strategy)

print("\n" + "=" * 70)
print("🎯 IMMEDIATE ACTION ITEMS")
print("=" * 70)
print("""
1. Pick 2-3 targets from Tier 2 (newer = less hunted)
2. Read their FULL program scope (avoid exclusions!)
3. Run parallel scans:
   - Subdomain enumeration
   - CORS checking
   - Security headers audit
   - Open redirect testing
4. Document EVERYTHING for reports
5. Focus on IMPACT - what damage could an attacker do?
""")
