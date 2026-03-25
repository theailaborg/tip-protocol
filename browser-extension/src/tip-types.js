/**
 * @file src/tip-types.js
 * @description TIP Protocol v2.0 - Platform registry and content type definitionss.
 *
 * Shared between popup.html, options.html, and content.js.
 * Mirrors the mobile web app's TipReg module so CTID construction
 * is identical across all TIP surfaces.
 *
 * The CTID formula is: SHAKE-256(buildContentString(type, fields))[:14]
 * What goes into the content string determines what the creator's signature
 * actually binds. An Instagram photo and a tweet are not the same kind of
 * content  -  they must not produce CTIDs from the same naive textarea.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

export const TIP_PLATFORMS = [
  { id:"instagram", name:"Instagram",  bg:"#E1306C", icon:"IG",
    types:["photo","carousel","reel","story"] },
  { id:"facebook",  name:"Facebook",   bg:"#1877F2", icon:"FB",
    types:["text","photo","video","audio","link"] },
  { id:"twitter",   name:"X / Twitter",bg:"#111111", icon:"X",
    types:["tweet","tweet_img","tweet_vid","thread"] },
  { id:"youtube",   name:"YouTube",    bg:"#FF0000", icon:"YT",
    types:["video"] },
  { id:"tiktok",    name:"TikTok",     bg:"#010101", icon:"TT",
    types:["video"] },
  { id:"linkedin",  name:"LinkedIn",   bg:"#0A66C2", icon:"in",
    types:["post","article","video","document"] },
  { id:"threads",   name:"Threads",    bg:"#000000", icon:"@",
    types:["text","photo","video"] },
  { id:"podcast",   name:"Podcast",    bg:"#8940E8", icon:"PC",
    types:["audio"] },
  { id:"news",      name:"News Media", bg:"#0C1A3A", icon:"NM",
    types:["news_article","photo_journalism","breaking_news","investigation",
           "live_blog","opinion","wire_adapted","correction"] },
  { id:"blog",      name:"Blog",       bg:"#0D7490", icon:"BL",
    types:["article"] },
  { id:"other",     name:"Other",      bg:"#8895A7", icon:"...",
    types:["text","photo","video","audio","article","document"] },
];

export const TIP_TYPES = {
  // Social media
  photo:      { label:"Photo",          sub:"Image + caption",        fields:["image","content"],              hashKeys:["Image pHash","Caption text"],                  contentLabel:"Caption",        placeholder:"Add a caption..." },
  carousel:   { label:"Carousel",       sub:"Multiple images + caption", fields:["carousel","content"],         hashKeys:["All image pHashes (ordered)","Caption text"],  contentLabel:"Caption",        placeholder:"Add a caption..." },
  reel:       { label:"Reel / Short",   sub:"Video URL + caption",    fields:["video_url","content"],          hashKeys:["Canonical video URL","Caption text"],           contentLabel:"Caption",        urlLabel:"Video URL" },
  story:      { label:"Story",          sub:"Image + text overlay",   fields:["image","story_text"],           hashKeys:["Image pHash","Story text overlay"] },
  text:       { label:"Text post",      sub:"Written post or status", fields:["content"],                      hashKeys:["Full post text"],                               contentLabel:"Post text",      placeholder:"Write your post..." },
  video:      { label:"Video",          sub:"URL + title + description", fields:["video_url","title","content"], hashKeys:["Canonical video URL","Title","Description"],  contentLabel:"Description",    urlLabel:"Video URL" },
  audio:      { label:"Audio",          sub:"File + title + show notes", fields:["audio","title","content"],    hashKeys:["Audio SHA-256","Episode title","Show notes"],  contentLabel:"Show notes",     titleRequired:true },
  link:       { label:"Link + comment", sub:"Shared URL + your text", fields:["link_url","content"],           hashKeys:["Link URL","Comment text"],                      contentLabel:"Your comment",   placeholder:"What do you want to say about this?" },
  tweet:      { label:"Tweet",          sub:"Up to 280 characters",   fields:["content"],                      hashKeys:["Tweet text (exact)"],                           contentLabel:"Tweet",          placeholder:"What's on your mind?", limit:280 },
  tweet_img:  { label:"Tweet + image",  sub:"Text + image",           fields:["image","content"],              hashKeys:["Image pHash","Tweet text"],                     contentLabel:"Tweet",          limit:280 },
  tweet_vid:  { label:"Tweet + video",  sub:"Text + video URL",       fields:["video_url","content"],          hashKeys:["Video URL","Tweet text"],                       contentLabel:"Tweet",          urlLabel:"Video URL", limit:280 },
  thread:     { label:"Thread",         sub:"Series of connected posts", fields:["thread"],                    hashKeys:["All posts joined in order"] },
  post:       { label:"Post",           sub:"Short-form update",      fields:["content"],                      hashKeys:["Post text"],                                    contentLabel:"Post",           placeholder:"Write your post..." },
  article:    { label:"Article",        sub:"Canonical URL + body",   fields:["video_url","title","content"],  hashKeys:["Canonical URL","Title","Body text"],            contentLabel:"Article text",   urlLabel:"Article URL" },
  document:   { label:"Document",       sub:"File + title",           fields:["document","title"],             hashKeys:["Document SHA-256","Title"],                     titleRequired:true },

  // News Media
  news_article: {
    label:"News article", sub:"Headline + URL + byline",
    fields:["video_url","title","news_byline","news_section","content"],
    hashKeys:["Canonical permalink","Headline","Byline","Section","Summary / lead"],
    urlLabel:"Published URL", titleLabel:"Headline", contentLabel:"Summary / lead paragraph",
    placeholder:"Opening paragraph or article summary...",
  },
  photo_journalism: {
    label:"Photo journalism", sub:"Image + cutline + location",
    fields:["image","title","news_location","content"],
    hashKeys:["Image pHash","Caption / cutline","Location"],
    titleLabel:"Caption / cutline", contentLabel:"Context / background",
    placeholder:"Names of subjects, what was happening...",
  },
  breaking_news: {
    label:"Breaking news", sub:"Developing story",
    fields:["video_url","title","news_byline","content"],
    hashKeys:["Story URL","Headline","Byline","Current confirmed summary"],
    urlLabel:"Story URL", titleLabel:"Headline", contentLabel:"What is confirmed so far",
    placeholder:"What is confirmed? What is still developing?",
  },
  investigation: {
    label:"Investigation", sub:"Long-form / series",
    fields:["video_url","title","news_byline","news_series","content"],
    hashKeys:["Canonical URL","Headline","Byline","Series name","Summary of findings"],
    urlLabel:"Published URL", titleLabel:"Article headline", contentLabel:"Summary of findings",
    placeholder:"What did you find?",
  },
  live_blog: {
    label:"Live blog", sub:"Real-time event coverage",
    fields:["video_url","title","news_byline","thread"],
    hashKeys:["Live blog URL","Event title","Byline","All updates joined in order"],
    urlLabel:"Live blog URL", titleLabel:"Event / story title",
  },
  opinion: {
    label:"Opinion / Editorial", sub:"Analysis, column, editorial",
    fields:["video_url","title","news_byline","news_opinion_type","content"],
    hashKeys:["Canonical URL","Headline","Byline","Article type","Summary / opening argument"],
    urlLabel:"Published URL", titleLabel:"Headline", contentLabel:"Summary / opening argument",
    placeholder:"Your central thesis or argument...",
  },
  wire_adapted: {
    label:"Wire adaptation", sub:"Wire service base + your work",
    fields:["video_url","title","news_byline","news_wire_source","content"],
    hashKeys:["Your published URL","Headline","Byline","Wire service source","What you added"],
    urlLabel:"Your published URL", titleLabel:"Headline", contentLabel:"What you added or changed",
    placeholder:"Describe your original contributions...",
    forcedOrigins:["AA","MX"],
    forcedNote:"Wire adaptations require AA or MX. OH is not appropriate when wire service text is substantially reprinted.",
  },
  correction: {
    label:"Correction", sub:"Corrects a previous CTID",
    fields:["video_url","title","news_ctid_original","content"],
    hashKeys:["Corrected article URL","Corrected headline","Original CTID","Correction description"],
    urlLabel:"Corrected article URL", titleLabel:"Corrected headline",
    contentLabel:"What was corrected", placeholder:"Describe the error and correction precisely...",
  },
};

/**
 * Build the canonical content string for SHAKE-256 hashing.
 * Must be called with the same fields the user filled on the relevant platform.
 *
 * @param {string} typeId  - key into TIP_TYPES
 * @param {Object} values  - map of field keys to string values
 *   Recognised keys: video_url, link_url, title, news_byline, news_section,
 *   news_location, news_series, news_wire_source, news_ctid_original,
 *   news_opinion_type, content, story_text,
 *   thread (array of strings), threadPosts (array of strings)
 * @returns {string}
 */
export function buildContentString(typeId, values) {
  const type = TIP_TYPES[typeId];
  if (!type) return values.content || values.title || "";

  const f = type.fields;

  // Thread types: join all posts
  if (f.includes("thread")) {
    const posts = values.thread || values.threadPosts || [];
    return posts.filter(p => (p || "").trim()).join("\n\n---\n\n");
  }

  const parts = [];
  if (f.includes("video_url")         && values.video_url)          parts.push(values.video_url.trim());
  if (f.includes("link_url")          && values.link_url)           parts.push(values.link_url.trim());
  if (f.includes("title")             && values.title)              parts.push(values.title.trim());
  if (f.includes("news_byline")       && values.news_byline)        parts.push(values.news_byline.trim());
  if (f.includes("news_section")      && values.news_section)       parts.push(values.news_section.trim());
  if (f.includes("news_location")     && values.news_location)      parts.push(values.news_location.trim());
  if (f.includes("news_series")       && values.news_series)        parts.push(values.news_series.trim());
  if (f.includes("news_wire_source")  && values.news_wire_source)   parts.push("Wire:" + values.news_wire_source.trim());
  if (f.includes("news_ctid_original")&& values.news_ctid_original) parts.push("Corrects:" + values.news_ctid_original.trim());
  if (f.includes("news_opinion_type") && values.news_opinion_type)  parts.push("[" + values.news_opinion_type.trim() + "]");
  if (f.includes("content")           && values.content)            parts.push(values.content.trim());
  if (f.includes("story_text")        && values.story_text)         parts.push(values.story_text.trim());

  return parts.join("\n");
}

/** @returns {string[]} Codes allowed for wire_adapted (AA, MX) */
export const WIRE_FORCED_ORIGINS = ["AA","MX"];

export const ORIGIN_COLORS = {
  OH:"#2563A8", AA:"#7C3AED", AG:"#C07318", MX:"#8895A7"
};
export const ORIGIN_LABELS = {
  OH:"Original Human", AA:"AI-Assisted", AG:"AI-Generated", MX:"Mixed"
};
export const ORIGIN_HINTS = {
  OH:"Declaring Original Human means you created this without AI. If an AI classifier later disputes this, your trust score may be affected.",
  AA:"AI-Assisted is honest and safe. No penalty for over-declaring AI involvement. Use this when AI helped but you led the work.",
  AG:"AI-Generated is always accepted. Full transparency builds long-term audience trust.",
  MX:"Mixed is a safe default when you are unsure about the human/AI balance.",
};
