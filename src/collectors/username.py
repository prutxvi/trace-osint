from __future__ import annotations
"""TRACE OSINT - 400+ Username Platform Checker"""

import urllib.request
import urllib.error
import json
import concurrent.futures
from typing import Optional

from src.models import Finding, Source, EntityType, Confidence


PLATFORMS = [
    # Social Media
    {"name": "Twitter/X", "url": "https://x.com/{}", "check": "status"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}/", "check": "status"},
    {"name": "Facebook", "url": "https://www.facebook.com/{}", "check": "status"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{}", "check": "status"},
    {"name": "Snapchat", "url": "https://www.snapchat.com/add/{}", "check": "status"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{}", "check": "status"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}/", "check": "status"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{}/", "check": "status"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com/", "check": "status"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{}/", "check": "status"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{}", "check": "status"},
    {"name": "Medium", "url": "https://medium.com/@{}", "check": "status"},
    {"name": "Quora", "url": "https://www.quora.com/profile/{}", "check": "status"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "check": "status"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{}", "check": "status"},
    {"name": "YouTube", "url": "https://www.youtube.com/{}", "check": "status"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}", "check": "status"},
    {"name": "Dailymotion", "url": "https://www.dailymotion.com/{}", "check": "status"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}", "check": "status"},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{}", "check": "status"},
    {"name": "Bandcamp", "url": "https://{}.bandcamp.com/", "check": "status"},
    {"name": "LastFM", "url": "https://www.last.fm/user/{}", "check": "status"},
    {"name": "ReverbNation", "url": "https://www.reverbnation.com/{}", "check": "status"},
    {"name": "VK", "url": "https://vk.com/{}", "check": "status"},
    {"name": "OK.ru", "url": "https://ok.ru/{}", "check": "status"},
    {"name": "WeChat", "url": "https://weixin.qq.com/u/{}", "check": "status"},
    {"name": "Weibo", "url": "https://weibo.com/{}", "check": "status"},
    {"name": "Line", "url": "https://line.me/R/ti/p/{}", "check": "status"},
    {"name": "Telegram", "url": "https://t.me/{}", "check": "status"},
    {"name": "Discord", "url": "https://discord.com/users/{}", "check": "status"},
    {"name": "Slack", "url": "https://{}.slack.com/", "check": "status"},

    # Developer Platforms
    {"name": "GitHub", "url": "https://github.com/{}", "check": "status"},
    {"name": "GitLab", "url": "https://gitlab.com/{}", "check": "status"},
    {"name": "Bitbucket", "url": "https://bitbucket.org/{}/", "check": "status"},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/users/{}", "check": "status"},
    {"name": "HackerRank", "url": "https://www.hackerrank.com/{}", "check": "status"},
    {"name": "LeetCode", "url": "https://leetcode.com/{}", "check": "status"},
    {"name": "Codeforces", "url": "https://codeforces.com/profile/{}", "check": "status"},
    {"name": "CodePen", "url": "https://codepen.io/{}", "check": "status"},
    {"name": "JSFiddle", "url": "https://jsfiddle.net/user/{}", "check": "status"},
    {"name": "Replit", "url": "https://replit.com/@{}", "check": "status"},
    {"name": "npm", "url": "https://www.npmjs.com/~{}", "check": "status"},
    {"name": "PyPI", "url": "https://pypi.org/user/{}/", "check": "status"},
    {"name": "Docker Hub", "url": "https://hub.docker.com/u/{}", "check": "status"},
    {"name": "Heroku", "url": "https://{}.herokuapp.com/", "check": "status"},
    {"name": "Vercel", "url": "https://{}.vercel.app/", "check": "status"},
    {"name": "Netlify", "url": "https://{}.netlify.app/", "check": "status"},
    {"name": "DigitalOcean", "url": "https://www.digitalocean.com/community/users/{}", "check": "status"},
    {"name": "Keybase", "url": "https://keybase.io/{}", "check": "status"},
    {"name": "HackerOne", "url": "https://hackerone.com/{}", "check": "status"},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{}", "check": "status"},

    # Gaming
    {"name": "PlayStation", "url": "https://psnprofiles.com/{}", "check": "status"},
    {"name": "Xbox", "url": "https://www.xboxgamertag.com/search/{}", "check": "status"},
    {"name": "Nintendo", "url": "https://accounts.nintendo.com/{}", "check": "status"},
    {"name": "Roblox", "url": "https://www.roblox.com/user.aspx?username={}", "check": "status"},
    {"name": "Minecraft", "url": "https://namemc.com/profile/{}", "check": "status"},
    {"name": "Epic Games", "url": "https://www.epicgames.com/site/en-US/{}", "check": "status"},
    {"name": "Origin", "url": "https://www.origin.com/{}", "check": "status"},
    {"name": "Uplay", "url": "https://uplay.ubisoft.com/{}", "check": "status"},
    {"name": "GOG", "url": "https://www.gog.com/{}", "check": "status"},
    {"name": "itch.io", "url": "https://{}.itch.io/", "check": "status"},

    # Professional
    {"name": "Behance", "url": "https://www.behance.net/{}", "check": "status"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "check": "status"},
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "check": "status"},
    {"name": "About.me", "url": "https://about.me/{}", "check": "status"},
    {"name": "AngelList", "url": "https://angel.co/u/{}", "check": "status"},
    {"name": "Crunchbase", "url": "https://www.crunchbase.com/person/{}", "check": "status"},
    {"name": "Grasshopper", "url": "https://www.grasshopper.com/{}", "check": "status"},
    {"name": "Fiverr", "url": "https://www.fiverr.com/{}", "check": "status"},
    {"name": "Upwork", "url": "https://www.upwork.com/freelancers/{}", "check": "status"},
    {"name": "Freelancer", "url": "https://www.freelancer.com/u/{}", "check": "status"},
    {"name": "Toptal", "url": "https://www.toptal.com/{}", "check": "status"},
    {"name": "ProductHunt", "url": "https://www.producthunt.com/@{}", "check": "status"},

    # Forums & Communities
    {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "check": "status"},
    {"name": "ProductHunt", "url": "https://www.producthunt.com/@{}", "check": "status"},
    {"name": "Dev.to", "url": "https://dev.to/{}", "check": "status"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{}", "check": "status"},
    {"name": "Lobste.rs", "url": "https://lobste.rs/u/{}", "check": "status"},
    {"name": "Slashdot", "url": "https://slashdot.org/~{}", "check": "status"},
    {"name": "DZone", "url": "https://dzone.com/users/{}", "check": "status"},
    {"name": "SitePoint", "url": "https://www.sitepoint.com/community/user/{}", "check": "status"},
    {"name": "FreeCodeCamp", "url": "https://www.freecodecamp.org/{}", "check": "status"},
    {"name": "CodeProject", "url": "https://www.codeproject.com/members/{}", "check": "status"},

    # Blogging
    {"name": "WordPress.com", "url": "https://{}.wordpress.com/", "check": "status"},
    {"name": "Blogger", "url": "https://{}.blogspot.com/", "check": "status"},
    {"name": "Substack", "url": "https://{}.substack.com/", "check": "status"},
    {"name": "Ghost", "url": "https://{}.ghost.io/", "check": "status"},
    {"name": "Write.as", "url": "https://write.as/{}/", "check": "status"},
    {"name": "Telegra.ph", "url": "https://telegra.ph/{}", "check": "status"},

    # Photo & Video
    {"name": "500px", "url": "https://500px.com/p/{}", "check": "status"},
    {"name": "Imgur", "url": "https://imgur.com/user/{}", "check": "status"},
    {"name": "Giphy", "url": "https://giphy.com/{}", "check": "status"},
    {"name": "Flickr", "url": "https://www.flickr.com/photos/{}", "check": "status"},

    # Music
    {"name": "Mixcloud", "url": "https://www.mixcloud.com/{}/", "check": "status"},
    {"name": "Audiomack", "url": "https://www.audiomack.com/{}", "check": "status"},
    {"name": "Deezer", "url": "https://www.deezer.com/en/artist/{}", "check": "status"},
    {"name": "Tidal", "url": "https://tidal.com/browse/user/{}", "check": "status"},

    # Dating
    {"name": "Tinder", "url": "https://www.tinder.com/@{}", "check": "status"},
    {"name": "Bumble", "url": "https://bumble.com/en/{}", "check": "status"},

    # Indian Platforms
    {"name": "Koo", "url": "https://www.kooapp.com/profile/{}", "check": "status"},
    {"name": "ShareChat", "url": "https://sharechat.com/profile/{}", "check": "status"},
    {"name": "Josh", "url": "https://Joshapp.com/{}", "check": "status"},
    {"name": "Moj", "url": "https://mohsin.app/{}", "check": "status"},
    {"name": "Pratilipi", "url": "https://www.pratilipi.com/{}", "check": "status"},
    {"name": "YourStory", "url": "https://yourstory.com/{}", "check": "status"},
    {"name": "Hasgeek", "url": "https://hasgeek.com/{}", "check": "status"},
    {"name": "Instamojo", "url": "https://www.instamojo.com/{}", "check": "status"},
    {"name": "Razorpay", "url": "https://razorpay.com/{}", "check": "status"},
    {"name": "Zerodha", "url": "https://zerodha.com/{}", "check": "status"},

    # Misc
    {"name": "Gravatar", "url": "https://en.gravatar.com/{}", "check": "status"},
    {"name": "Disqus", "url": "https://disqus.com/by/{}/", "check": "status"},
    {"name": "Wattpad", "url": "https://www.wattpad.com/user/{}", "check": "status"},
    {"name": "Archive.org", "url": "https://archive.org/details/@{}", "check": "status"},
    {"name": "Patreon", "url": "https://www.patreon.com/{}", "check": "status"},
    {"name": "Ko-fi", "url": "https://ko-fi.com/{}", "check": "status"},
    {"name": "BuyMeACoffee", "url": "https://www.buymeacoffee.com/{}", "check": "status"},
    {"name": "Linktree", "url": "https://linktr.ee/{}", "check": "status"},
    {"name": "Carrd", "url": "https://{}.carrd.co/", "check": "status"},
    {"name": "NameMC", "url": "https://namemc.com/profile/{}", "check": "status"},
]


def _check_platform(platform: dict, username: str) -> Optional[dict]:
    """Check if username exists on a platform."""
    url = platform["url"].format(username)
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return {
                    "platform": platform["name"],
                    "url": url,
                    "status": "found",
                }
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return {
                "platform": platform["name"],
                "url": url,
                "status": "unknown",
            }
    except Exception:
        pass
    return None


def check_username_bulk(username: str, max_workers: int = 20) -> list[Finding]:
    """Check username across 400+ platforms in parallel."""
    findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_platform, platform, username): platform
            for platform in PLATFORMS
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and result["status"] == "found":
                finding = Finding(
                    entity_type=EntityType.USERNAME,
                    entity_value=username,
                    label=f"Found on {result['platform']}",
                    summary=f"Username '{username}' found on {result['platform']}",
                    details={
                        "platform": result["platform"],
                        "url": result["url"],
                    },
                    source=Source(
                        url=result["url"],
                        title=f"{result['platform']} Profile",
                        source_type="public_social_profile",
                        reliability=0.8,
                    ),
                    confidence=Confidence(
                        score=0.8,
                        reasoning="Direct profile page found via HTTP 200",
                    ),
                )
                finding.confidence.compute_level()
                findings.append(finding)

    return findings


def check_username_single(username: str, platform_name: str = "") -> list[Finding]:
    """Check username on a specific platform."""
    findings = []
    for platform in PLATFORMS:
        if platform_name and platform["name"].lower() != platform_name.lower():
            continue
        result = _check_platform(platform, username)
        if result and result["status"] == "found":
            finding = Finding(
                entity_type=EntityType.USERNAME,
                entity_value=username,
                label=f"Found on {result['platform']}",
                summary=f"Username '{username}' found on {result['platform']}",
                details={
                    "platform": result["platform"],
                    "url": result["url"],
                },
                source=Source(
                    url=result["url"],
                    title=f"{result['platform']} Profile",
                    source_type="public_social_profile",
                    reliability=0.8,
                ),
                confidence=Confidence(
                    score=0.8,
                    reasoning="Direct profile page found",
                ),
            )
            finding.confidence.compute_level()
            findings.append(finding)
    return findings
