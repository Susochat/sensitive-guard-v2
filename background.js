const DEFAULTS = {
  enabled: true,
  mode: 'block',
  aiOnly: false,
  allowlist: [],
  blocklist: [],
  customKeywords: ['confidential', 'internal only', 'do not share', 'production credential', 'secret', 'proprietary', 'customer data'],
  enabledDetectors: ['secret','credential','pii','financial','code','keyword'],
  stats: {blocked: 0, warned: 0, redacted: 0, lastEvents: []}
};
const AI_SITES = {
  'chatgpt.com':'ChatGPT','chat.openai.com':'ChatGPT','claude.ai':'Claude','gemini.google.com':'Gemini','aistudio.google.com':'Google AI Studio','perplexity.ai':'Perplexity','copilot.microsoft.com':'Microsoft Copilot','poe.com':'Poe','grok.com':'Grok','x.ai':'Grok','chat.deepseek.com':'DeepSeek','mistral.ai':'Mistral','lechat.mistral.ai':'Le Chat','notebooklm.google.com':'NotebookLM','meta.ai':'Meta AI','huggingface.co':'Hugging Face'};
chrome.runtime.onInstalled.addListener(async()=>{const cur=await chrome.storage.local.get(DEFAULTS); await chrome.storage.local.set({...DEFAULTS,...cur});});
chrome.runtime.onMessage.addListener((msg, sender, sendResponse)=>{
  if(msg.type==='event') recordEvent(msg.event).then(()=>sendResponse({ok:true}));
  if(msg.type==='getSiteInfo') sendResponse(siteInfo(msg.url));
  if(msg.type==='getDefaults') sendResponse(DEFAULTS);
  return true;
});
function siteInfo(url='') { try {const h=new URL(url).hostname.toLowerCase(); const key=Object.keys(AI_SITES).find(x=>h===x||h.endsWith('.'+x)); return {hostname:h, ai:!!key, name:key?AI_SITES[key]:h};} catch{return {hostname:'',ai:false,name:''};}}
async function recordEvent(event){
  const s=await chrome.storage.local.get(DEFAULTS); const stats={...DEFAULTS.stats,...(s.stats||{})};
  stats[event.action==='block'?'blocked':event.action==='warn'?'warned':'redacted']++;
  stats.lastEvents=[{...event,time:new Date().toISOString()},...(stats.lastEvents||[])].slice(0,50);
  await chrome.storage.local.set({stats});
}
