/**
 * @file tip-protocol/shared/platforms.js
 * @description URL-host → content-type-resolution-strategy registry. Used
 * by node/src/services/content-type.js as the second step in the ladder:
 * publisher hint → URL platform → shape heuristic.
 *
 * Strategies:
 *   "video" / "audio" / "image" / "text"  — fixed; ignores request shape
 *   "MEDIA_DOMINANT"   — media kind wins. Captions are captions. For
 *                        visual-first platforms where text is structurally
 *                        a secondary field (Instagram, TikTok, Pinterest).
 *   "MIXED"            — text+media may be co-equal:
 *                          text only           → text
 *                          multi-kind          → multi
 *                          video present       → video (attention-dominant)
 *                          audio present       → audio (attention-dominant)
 *                          image + text        → multi (genuinely ambiguous)
 *                          image only          → image
 *                        Used by X, FB, LinkedIn, Reddit, etc. where a
 *                        long post with one image might be text-as-work.
 *   "TEXT_DOMINANT"    — text wins if any text present (article platforms
 *                        with hero images / inline media).
 *
 * Aliases collapse synonym domains (twitter.com → x.com, youtu.be →
 * youtube.com) so the strategy table never duplicates per-platform behavior.
 * Add new regional TLDs / rebrands to PLATFORM_ALIASES, not to the
 * strategy table.
 *
 * Consensus model: the originating node resolves content_type once and
 * writes it to PRESCAN_COMPLETED; replay nodes read that tx and don't
 * re-derive. So divergent local tables (e.g. node-1 has tiktok mapping,
 * node-2 doesn't) never fork consensus — they just produce slightly
 * different content_type for the same URL, and everyone agrees on whichever
 * value the originating node committed.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const PLATFORM_ALIASES = Object.freeze({
  "twitter.com":       "x.com",
  "fb.com":            "facebook.com",
  "m.facebook.com":    "facebook.com",
  "youtu.be":          "youtube.com",
  "m.youtube.com":     "youtube.com",
  "music.youtube.com": "youtube.com",
  "bbc.co.uk":         "bbc.com",
  "open.spotify.com":  "spotify.com",
  "on.soundcloud.com": "soundcloud.com",
});

const PLATFORM_CONTENT_TYPE = Object.freeze({
  // FIXED — single-modality platforms
  "youtube.com":        "video",
  "vimeo.com":          "video",
  "spotify.com":        "audio",
  "podcasts.apple.com": "audio",
  "soundcloud.com":     "audio",

  // MEDIA_DOMINANT — visual-first, captions are captions
  "instagram.com": "MEDIA_DOMINANT",
  "tiktok.com":    "MEDIA_DOMINANT",
  "pinterest.com": "MEDIA_DOMINANT",

  // MIXED — text and media may be co-equal
  "x.com":           "MIXED",
  "facebook.com":    "MIXED",
  "linkedin.com":    "MIXED",
  "reddit.com":      "MIXED",
  "threads.net":     "MIXED",
  "truthsocial.com": "MIXED",
  "weibo.com":       "MIXED",
  "wechat.com":      "MIXED",
  // Top Mastodon instances — federated platform; long-tail instances
  // fall through to shape heuristic since the fediverse can't be enumerated.
  "mastodon.social": "MIXED",
  "mastodon.online": "MIXED",
  "fosstodon.org":   "MIXED",
  "mas.to":          "MIXED",
  "hachyderm.io":    "MIXED",

  // TEXT_DOMINANT — text is the work even with hero image / inline media
  "medium.com":         "TEXT_DOMINANT",
  "substack.com":       "TEXT_DOMINANT",
  "scribd.com":         "TEXT_DOMINANT",
  "slideshare.net":     "TEXT_DOMINANT",
  "wordpress.com":      "TEXT_DOMINANT",
  "blogspot.com":       "TEXT_DOMINANT",
  "tumblr.com":         "TEXT_DOMINANT",
  "ghost.io":           "TEXT_DOMINANT",
  "nytimes.com":        "TEXT_DOMINANT",
  "wsj.com":            "TEXT_DOMINANT",
  "reuters.com":        "TEXT_DOMINANT",
  "apnews.com":         "TEXT_DOMINANT",
  "bbc.com":            "TEXT_DOMINANT",
  "boomlive.in":        "TEXT_DOMINANT",
  "theguardian.com":    "TEXT_DOMINANT",
  "washingtonpost.com": "TEXT_DOMINANT",
});

const PLATFORM_STRATEGY_VALUES = Object.freeze(
  new Set(["video", "audio", "image", "text", "MEDIA_DOMINANT", "MIXED", "TEXT_DOMINANT"])
);

module.exports = {
  PLATFORM_ALIASES,
  PLATFORM_CONTENT_TYPE,
  PLATFORM_STRATEGY_VALUES,
};
