// Shared detector definitions. Loaded by content.js only; network-guard.js has a compact copy.
const DETECTORS = [
 {id:'secret',label:'API / access secret',severity:'critical',patterns:[/\bsk-[A-Za-z0-9_-]{20,}\b/g,/\bAKIA[0-9A-Z]{16}\b/g,/\bAIza[0-9A-Za-z_-]{20,}\b/g,/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,/\bglpat-[A-Za-z0-9_-]{20,}\b/g]},
 {id:'credential',label:'Credential / password',severity:'critical',patterns:[/(password|passwd|pwd|secret|api[_ -]?key|access[_ -]?token)\s*[:=]\s*['"`]?[^\s'"`]{6,}/gi,/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g]},
 {id:'pii',label:'Personal information',severity:'high',patterns:[/\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,/(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)/g,/\b(?:\+?91[- .]?)?[6-9]\d{9}\b/g,/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,/\b\d{3}-\d{2}-\d{4}\b/g]},
 {id:'financial',label:'Financial data',severity:'high',patterns:[/\b(?:\d[ -]?){13,19}\b/g,/\b(?:IFSC|MICR)\s*[:=-]?\s*[A-Z0-9]{8,12}\b/gi]},
 {id:'code',label:'Source code / internal code',severity:'medium',patterns:[/\b(?:BEGIN|END)\s+(?:RSA|OPENSSH|EC|PGP)\b/g,/\b(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\s+FROM\s+/gi,/\b(?:AKAMAI|INTERNAL|PROD|STAGING)_[A-Z0-9_]{4,}\b/g]},
];
function analyzeText(text, settings={}){
  const enabled=new Set(settings.enabledDetectors||DETECTORS.map(d=>d.id)); const findings=[]; const seen=new Set();
  for(const d of DETECTORS){ if(!enabled.has(d.id)) continue; for(const p0 of d.patterns){const p=new RegExp(p0.source,p0.flags); let m; while((m=p.exec(text))){const value=m[0]; const key=d.id+'|'+m.index+'|'+value.slice(0,80); if(!seen.has(key)){seen.add(key); findings.push({id:d.id,label:d.label,severity:d.severity,start:m.index,end:m.index+value.length,match:value});} if(!p.global) break;}}}
  for(const kw of (settings.customKeywords||[])){ if(!kw) continue; const i=text.toLowerCase().indexOf(kw.toLowerCase()); if(i>=0) findings.push({id:'keyword',label:'Sensitive keyword',severity:'medium',start:i,end:i+kw.length,match:text.slice(i,i+kw.length)}); }
  return findings.sort((a,b)=>a.start-b.start);
}
function redactText(text, findings){let out=text; [...findings].sort((a,b)=>b.start-a.start).forEach(f=>{out=out.slice(0,f.start)+'[REDACTED:'+f.label.toUpperCase()+']'+out.slice(f.end);}); return out;}
function riskLevel(findings){ if(findings.some(x=>x.severity==='critical')) return 'critical'; if(findings.some(x=>x.severity==='high')) return 'high'; if(findings.length) return 'medium'; return 'none'; }
