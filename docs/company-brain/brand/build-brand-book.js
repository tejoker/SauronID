const pptxgen = require('pptxgenjs');
const {
  imageSizingContain,
  imageSizingCrop,
  svgToDataUri,
  safeOuterShadow,
  warnIfSlideHasOverlaps,
  warnIfSlideElementsOutOfBounds,
} = require('/home/oai/skills/slides/pptxgenjs_helpers');

const pptx = new pptxgen();
pptx.layout = 'LAYOUT_WIDE';
pptx.author = 'OpenAI';
pptx.company = 'SauronID';
pptx.subject = 'SauronID Brand and Positioning System v2.0';
pptx.title = 'SauronID Brand System v2.0';
pptx.lang = 'en-US';
pptx.theme = {
  headFontFace: 'Inter',
  bodyFontFace: 'Inter',
  lang: 'en-US',
};
pptx.defineSlideMaster({
  title: 'LIGHT',
  background: { color: 'F7FAFF' },
  objects: [
    { rect: { x: 0, y: 0, w: 13.333, h: 0.055, fill: { color: '0054F3' }, line: { color: '0054F3' } } },
  ],
  slideNumber: { x: 12.48, y: 7.04, w: 0.36, h: 0.18, fontFace: 'Inter', fontSize: 7.5, color: '8B98B3', align: 'right', margin: 0 },
});
pptx.defineSlideMaster({
  title: 'DARK',
  background: { color: '000D35' },
  objects: [
    { rect: { x: 0, y: 0, w: 13.333, h: 0.055, fill: { color: '2384FB' }, line: { color: '2384FB' } } },
  ],
  slideNumber: { x: 12.48, y: 7.04, w: 0.36, h: 0.18, fontFace: 'Inter', fontSize: 7.5, color: '78C6FB', align: 'right', margin: 0 },
});

const C = {
  midnight: '000D35',
  navy: '000F3B',
  navy2: '071B51',
  signal: '0054F3',
  orbit: '2384FB',
  sky: '78C6FB',
  cloud: 'F7FAFF',
  soft: 'EEF4FF',
  ink: '071229',
  slate: '60708F',
  slate2: '8B98B3',
  white: 'FFFFFF',
  border: 'D7E1F1',
  border2: 'E8EEF8',
  allowed: '0C9B8E',
  allowedSoft: 'EAF8F5',
  review: 'D69020',
  reviewSoft: 'FFF7E8',
  stopped: 'D94C64',
  stoppedSoft: 'FFF0F3',
  running: '6C63E8',
  runningSoft: 'F1EFFF',
};

const A = '/mnt/data/sauronid_brand_v2_work/build/assets';
const LOGO = `${A}/SauronID_Logo.png`;
const SCREEN_OVERVIEW = `${A}/dashboard-overview.png`;
const SCREEN_AGENT = `${A}/dashboard-agent.png`;
const SCREEN_WELCOME = `${A}/dashboard-welcome.png`;
const SCREEN_PROOFS = `${A}/dashboard-proofs.png`;
const FONT = 'Inter';
const DISPLAY = 'Inter';
const MONO = 'DejaVu Sans Mono';
const SW = 13.333;
const SH = 7.5;

function addSources(slide, lines) {
  if (!lines || !lines.length) return;
  slide.addNotes(`[Sources]\n${lines.map(s => `- ${s}`).join('\n')}\n[/Sources]`);
}
function addSectionLabel(slide, text, dark=false) {
  slide.addText(text.toUpperCase(), {
    x: 0.66, y: 0.34, w: 5.3, h: 0.20,
    fontFace: FONT, fontSize: 8.3, bold: true,
    color: dark ? C.sky : C.signal, charSpacing: 1.6,
    margin: 0,
  });
}
function addTitle(slide, title, subtitle='', dark=false, width=9.4) {
  slide.addText(title, {
    x: 0.66, y: 0.70, w: width, h: 0.72,
    fontFace: DISPLAY, fontSize: 29.5, bold: true,
    color: dark ? C.white : C.ink, margin: 0,
    fit: 'shrink', breakLine: false,
  });
  if (subtitle) {
    slide.addText(subtitle, {
      x: 0.68, y: 1.43, w: Math.min(width, 9.5), h: 0.52,
      fontFace: FONT, fontSize: 12.2,
      color: dark ? 'BFD8FF' : C.slate, margin: 0,
      fit: 'shrink', breakLine: false,
    });
  }
}
function addFooter(slide, dark=false) {
  slide.addText('SAURONID  /  BRAND SYSTEM V2.0', {
    x: 0.66, y: 7.02, w: 4.4, h: 0.16,
    fontFace: FONT, fontSize: 7.2, bold: true,
    color: dark ? '6EAFFF' : C.slate2, charSpacing: 1.1,
    margin: 0,
  });
}
function addCard(slide, x, y, w, h, opts={}) {
  const dark = opts.dark || false;
  slide.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h,
    rectRadius: opts.radius || 0.15,
    fill: { color: opts.fill || (dark ? C.navy2 : C.white), transparency: opts.transparency || 0 },
    line: { color: opts.line || (dark ? '1D4A94' : C.border), transparency: opts.lineTransparency || 0, width: opts.lineWidth || 0.8 },
    shadow: opts.shadow === false ? undefined : safeOuterShadow('000D35', 0.10, 45, 2.1, 1.0),
  });
}
function addPill(slide, text, x, y, w, opts={}) {
  const dark = opts.dark || false;
  slide.addShape(pptx.ShapeType.roundRect, {
    x, y, w, h: opts.h || 0.34,
    rectRadius: 0.10,
    fill: { color: opts.fill || (dark ? C.navy2 : C.white), transparency: opts.transparency || 0 },
    line: { color: opts.line || (dark ? '1D4A94' : C.border), width: 0.8 },
  });
  slide.addText(text, {
    x: x + 0.07, y: y + 0.07, w: w - 0.14, h: (opts.h || 0.34) - 0.12,
    fontFace: FONT, fontSize: opts.fontSize || 8.2, bold: true,
    color: opts.color || (dark ? C.white : C.ink), align: 'center', margin: 0, fit: 'shrink',
  });
}
function addBody(slide, text, x, y, w, h, dark=false, fontSize=11.2, opts={}) {
  slide.addText(text, {
    x, y, w, h,
    fontFace: opts.fontFace || FONT, fontSize,
    color: opts.color || (dark ? 'C7DAF8' : C.slate),
    bold: opts.bold || false, italic: opts.italic || false,
    margin: opts.margin === undefined ? 0 : opts.margin,
    valign: opts.valign || 'top', fit: 'shrink', breakLine: false,
    paraSpaceAfterPt: opts.paraSpaceAfterPt || 4,
  });
}
function addCardTitle(slide, text, x, y, w, dark=false, size=16.5) {
  slide.addText(text, {
    x, y, w, h: 0.34,
    fontFace: DISPLAY, fontSize: size, bold: true,
    color: dark ? C.white : C.ink, margin: 0, fit: 'shrink',
  });
}
function addBulletList(slide, items, x, y, w, h, dark=false, fontSize=10.8, color) {
  const runs = [];
  items.forEach((it, i) => runs.push({ text: it, options: { bullet: { indent: 11 }, hanging: 3, breakLine: i < items.length - 1 } }));
  slide.addText(runs, {
    x, y, w, h, fontFace: FONT, fontSize,
    color: color || (dark ? 'C7DAF8' : C.slate),
    margin: 0.02, valign: 'top', paraSpaceAfterPt: 6, fit: 'shrink',
  });
}
function addLogoLockup(slide, x, y, scale=1, dark=false) {
  const size = 0.63 * scale;
  slide.addImage({ path: LOGO, ...imageSizingContain(LOGO, x, y, size, size) });
  slide.addText('SauronID', {
    x: x + size + 0.12 * scale, y: y + 0.12 * scale,
    w: 2.0 * scale, h: 0.38 * scale,
    fontFace: DISPLAY, fontSize: 21 * scale, bold: true,
    color: dark ? C.white : C.ink, margin: 0, fit: 'shrink',
  });
}
function addStatus(slide, label, x, y, type='allowed', w=1.25) {
  const map = {
    allowed: [C.allowedSoft, C.allowed, 'ALLOWED'],
    review: [C.reviewSoft, C.review, 'NEEDS APPROVAL'],
    stopped: [C.stoppedSoft, C.stopped, 'STOPPED'],
    running: [C.runningSoft, C.running, 'RUNNING'],
  };
  const [fill, color, fallback] = map[type];
  addPill(slide, label || fallback, x, y, w, { fill, color, line: fill, fontSize: 7.7 });
}
function simpleIcon(kind, color='0054F3', bg='EEF4FF') {
  let inner = '';
  if (kind === 'intent') inner = '<path d="M29 51c12-20 30-30 53-30-4 22-16 39-38 51-8 4-17-2-15-21z" fill="none" stroke="#'+color+'" stroke-width="6" stroke-linejoin="round"/><circle cx="58" cy="44" r="7" fill="#'+color+'"/>';
  if (kind === 'tools') inner = '<circle cx="35" cy="35" r="12" fill="none" stroke="#'+color+'" stroke-width="6"/><circle cx="72" cy="67" r="12" fill="none" stroke="#'+color+'" stroke-width="6"/><path d="M45 43l17 16M28 50l-8 18M80 52l7-20" stroke="#'+color+'" stroke-width="6" stroke-linecap="round"/>';
  if (kind === 'bounds') inner = '<rect x="23" y="22" width="54" height="56" rx="14" fill="none" stroke="#'+color+'" stroke-width="6"/><path d="M36 51l10 10 20-23" fill="none" stroke="#'+color+'" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>';
  if (kind === 'run') inner = '<path d="M34 26l40 24-40 24z" fill="#'+color+'"/><circle cx="50" cy="50" r="38" fill="none" stroke="#'+color+'" stroke-width="5" opacity=".35"/>';
  if (kind === 'proof') inner = '<path d="M28 27h44v46H28z" fill="none" stroke="#'+color+'" stroke-width="6"/><path d="M37 40h26M37 52h26M37 64h16" stroke="#'+color+'" stroke-width="5" stroke-linecap="round"/>';
  if (kind === 'approval') inner = '<path d="M24 50h52" stroke="#'+color+'" stroke-width="6" stroke-linecap="round"/><circle cx="50" cy="50" r="13" fill="#'+color+'"/><path d="M45 50l4 4 7-9" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect width="100" height="100" rx="24" fill="#${bg}"/>${inner}</svg>`;
}
function addIcon(slide, kind, x, y, size=0.5, color='0054F3', bg='EEF4FF') {
  slide.addImage({ data: svgToDataUri(simpleIcon(kind, color, bg)), x, y, w: size, h: size });
}
function orbitSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="700" viewBox="0 0 1200 700">
  <defs><radialGradient id="g" cx="75%" cy="22%"><stop offset="0" stop-color="#2384FB" stop-opacity=".26"/><stop offset="1" stop-color="#000D35" stop-opacity="0"/></radialGradient></defs>
  <rect width="1200" height="700" fill="#000D35"/><rect width="1200" height="700" fill="url(#g)"/>
  <ellipse cx="890" cy="335" rx="440" ry="202" fill="none" stroke="#17458F" stroke-width="2" opacity=".55" transform="rotate(-12 890 335)"/>
  <ellipse cx="890" cy="335" rx="342" ry="126" fill="none" stroke="#2384FB" stroke-width="13" opacity=".26" transform="rotate(10 890 335)"/>
  <ellipse cx="890" cy="335" rx="254" ry="82" fill="none" stroke="#78C6FB" stroke-width="3" opacity=".55" transform="rotate(-21 890 335)"/>
  </svg>`;
}
function lineArrow(slide, x1, y1, x2, y2, color=C.border, width=1.5, end='triangle') {
  slide.addShape(pptx.ShapeType.line, { x: x1, y: y1, w: x2-x1, h: y2-y1, line: { color, width, endArrowType: end } });
}
function addSlideSourcesFooter(slide, text, dark=false) {
  slide.addText(text, { x: 6.0, y: 7.02, w: 6.15, h: 0.16, fontFace: FONT, fontSize: 6.8, color: dark ? '6EAFFF' : C.slate2, margin: 0, align: 'right', fit: 'shrink' });
}

// 1 - Cover
{
  const slide = pptx.addSlide('DARK');
  slide.addImage({ data: svgToDataUri(orbitSvg()), x: 0, y: 0, w: SW, h: SH });
  slide.addShape(pptx.ShapeType.ellipse, { x: 8.08, y: 0.66, w: 4.48, h: 4.48, fill: { color: C.white, transparency: 94 }, line: { color: C.sky, transparency: 77, width: 1.1 } });
  slide.addImage({ path: LOGO, ...imageSizingContain(LOGO, 8.18, 0.76, 4.28, 4.28) });
  slide.addText('SAURONID', { x: 0.70, y: 1.02, w: 5.8, h: 0.30, fontFace: FONT, fontSize: 9.5, bold: true, color: C.sky, charSpacing: 2.8, margin: 0 });
  slide.addText('Brand and\npositioning system', { x: 0.66, y: 1.52, w: 7.0, h: 1.55, fontFace: DISPLAY, fontSize: 42, bold: true, color: C.white, margin: 0, breakLine: false, fit: 'shrink' });
  slide.addText('Build agents you can actually let act.', { x: 0.70, y: 3.42, w: 6.65, h: 0.86, fontFace: DISPLAY, fontSize: 26, bold: true, color: 'BFD8FF', margin: 0, fit: 'shrink' });
  slide.addText('A creation-first brand for an agent platform with boundaries built in.', { x: 0.72, y: 4.45, w: 5.85, h: 0.65, fontFace: FONT, fontSize: 12.5, color: '95B7E9', margin: 0, fit: 'shrink' });
  addPill(slide, 'V2.0  /  AUGUST 2026', 0.72, 5.95, 1.95, { dark: true, fill: '071B51', color: C.sky, line: '19458F' });
  slide.addText('Strategy, messaging, identity, launcher UX, website and go-to-market guidance.', { x: 0.74, y: 6.45, w: 6.25, h: 0.38, fontFace: FONT, fontSize: 9.2, color: '789ACD', margin: 0, fit: 'shrink' });
  addSources(slide, ['Internal: uploaded SauronID repository and founder product direction, August 2026.']);
}

// 2 - The shift
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '01 / Strategic shift');
  addTitle(slide, 'Security stays. The product changes.', 'Move the technical moat from the front door into the product experience.');
  addCard(slide, 0.68, 2.07, 5.70, 3.80, { fill: 'FFF5F7', line: 'F6CCD4', shadow: false });
  addPill(slide, 'OLD CENTER OF GRAVITY', 1.00, 2.40, 1.78, { fill: C.stoppedSoft, color: C.stopped, line: C.stoppedSoft });
  slide.addText('Add security to an\nalready-built agent.', { x: 1.00, y: 2.92, w: 4.65, h: 1.0, fontFace: DISPLAY, fontSize: 25, bold: true, color: C.ink, margin: 0, fit: 'shrink' });
  addBulletList(slide, ['Technical buyer first', 'Repository and integration first', 'Risk reduction as the primary value', 'Two adoption battles at once'], 1.00, 4.24, 4.55, 1.30, false, 10.5, C.slate);
  addCard(slide, 6.70, 2.07, 5.95, 3.80, { fill: C.midnight, line: C.midnight, shadow: false });
  addPill(slide, 'NEW CENTER OF GRAVITY', 7.04, 2.40, 1.92, { dark: true, fill: '0D2D70', color: C.sky, line: '2055A4' });
  slide.addText('Build the agent with\nboundaries from day one.', { x: 7.04, y: 2.92, w: 4.9, h: 1.0, fontFace: DISPLAY, fontSize: 25, bold: true, color: C.white, margin: 0, fit: 'shrink' });
  addBulletList(slide, ['Operator and domain expert first', 'Guided launcher first', 'Capability and adoption as the value', 'Security becomes the reason to trust action'], 7.04, 4.24, 4.75, 1.30, true, 10.5);
  slide.addText('The moat remains technical. The story becomes human.', { x: 0.72, y: 6.28, w: 11.7, h: 0.32, fontFace: DISPLAY, fontSize: 17, bold: true, color: C.signal, align: 'center', margin: 0 });
  addFooter(slide);
}

// 3 - Market reality
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '02 / Market reality', true);
  addTitle(slide, 'The market rewards access to outcomes', 'Winning platforms reduce the distance between a non-expert and a useful agent.', true);
  const metrics = [
    ['n8n', '200K+', 'users', '3,000+ enterprises'],
    ['Dify', '1.4M+', 'machines', '280+ enterprises'],
    ['Gumloop', '$50M', 'Series B', 'minimal learning curve'],
    ['Relevance AI', '40K', 'agents in Jan 2025', '$24M Series B'],
  ];
  const xs = [0.72, 3.77, 6.82, 9.87];
  metrics.forEach((m, i) => {
    addCard(slide, xs[i], 2.22, 2.75, 2.27, { fill: i % 2 ? '071B51' : '041747', line: '1D4A94', shadow: false });
    slide.addText(m[0].toUpperCase(), { x: xs[i]+0.22, y: 2.49, w: 2.2, h: 0.20, fontFace: FONT, fontSize: 8, bold: true, color: C.sky, charSpacing: 1.2, margin: 0 });
    slide.addText(m[1], { x: xs[i]+0.22, y: 2.89, w: 2.2, h: 0.52, fontFace: DISPLAY, fontSize: 25, bold: true, color: C.white, margin: 0 });
    slide.addText(m[2], { x: xs[i]+0.22, y: 3.45, w: 2.2, h: 0.28, fontFace: FONT, fontSize: 10.3, color: 'C7DAF8', margin: 0, fit: 'shrink' });
    slide.addText(m[3], { x: xs[i]+0.22, y: 3.88, w: 2.2, h: 0.32, fontFace: FONT, fontSize: 8.7, color: '85ABE1', margin: 0, fit: 'shrink' });
  });
  addCard(slide, 0.72, 4.90, 11.90, 1.24, { fill: '0D2D70', line: '2055A4', shadow: false });
  slide.addText('The signal is not "buyers want more security dashboards."', { x: 1.05, y: 5.18, w: 4.70, h: 0.30, fontFace: DISPLAY, fontSize: 15.5, bold: true, color: C.white, margin: 0, fit: 'shrink' });
  slide.addText('The signal is that people adopt tools that make building useful agents immediate, understandable and shareable.', { x: 6.35, y: 5.10, w: 5.55, h: 0.48, fontFace: FONT, fontSize: 11.0, color: 'C7DAF8', margin: 0, fit: 'shrink' });
  slide.addText('Reported company figures; not independently audited in this document.', { x: 0.74, y: 6.49, w: 6.1, h: 0.20, fontFace: FONT, fontSize: 7.4, italic: true, color: '789ACD', margin: 0 });
  addFooter(slide, true);
  addSlideSourcesFooter(slide, 'Sources: n8n, Dify, TechCrunch - accessed Aug 2026', true);
  addSources(slide, [
    'https://blog.n8n.io/series-b/',
    'https://dify.ai/about-us',
    'https://techcrunch.com/2026/03/12/gumloop-lands-50m-from-benchmark-to-turn-every-employee-into-an-ai-agent-builder/',
    'https://techcrunch.com/2025/05/06/relevance-ai-raises-24m-series-b-to-help-anyone-build-teams-of-ai-agents/'
  ]);
}

// 4 - Success patterns
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '03 / Adoption patterns');
  addTitle(slide, 'Six patterns behind successful adoption', 'Use the market as a product design brief, not a logo wall.');
  const items = [
    ['01', 'First value before setup', 'Dify added model credits and zero-config templates because API keys were a barrier.'],
    ['02', 'Non-technical builders', 'Gumloop and Relevance center the person who knows the workflow, not only the engineer.'],
    ['03', 'Templates create momentum', 'n8n and Dify turn reusable workflows into community and distribution.'],
    ['04', 'Model choice matters', 'Model-agnostic products let teams use the best model or existing credits.'],
    ['05', 'Desktop packaging wins', 'LM Studio made local models approachable by turning infrastructure into an app.'],
    ['06', 'Security enables speed', 'Auth0 sells agent identity as a way to ship faster, not as fear added after the fact.'],
  ];
  const positions = [[0.70,2.12],[4.50,2.12],[8.30,2.12],[0.70,4.32],[4.50,4.32],[8.30,4.32]];
  items.forEach((it, i) => {
    const [x,y]=positions[i];
    addCard(slide, x, y, 3.42, 1.72, { shadow: false, fill: i===0 ? 'EEF4FF' : C.white, line: i===0 ? 'B7D0F7' : C.border });
    slide.addText(it[0], { x:x+0.22,y:y+0.22,w:0.48,h:0.23,fontFace:MONO,fontSize:9,bold:true,color:C.signal,margin:0 });
    addCardTitle(slide, it[1], x+0.22, y+0.52, 2.95, false, 14.3);
    addBody(slide, it[2], x+0.22, y+0.92, 2.92, 0.58, false, 9.1);
  });
  addFooter(slide);
  addSlideSourcesFooter(slide, 'Sources: Dify, n8n, TechCrunch, LM Studio, Auth0', false);
  addSources(slide, [
    'https://dify.ai/ko/blog/try-openai-claude-gemini-grok-free-on-dify-cloud',
    'https://dify.ai/blog/kakaku-accelerates-ai-adoption-with-dify-fast-secure-and-scalable',
    'https://blog.n8n.io/series-b/',
    'https://www.lmstudio.ai/',
    'https://auth0.com/ai',
    'https://techcrunch.com/2026/03/12/gumloop-lands-50m-from-benchmark-to-turn-every-employee-into-an-ai-agent-builder/'
  ]);
}

// 5 - category map
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '04 / Category');
  addTitle(slide, 'Own the intersection, not the generic category', 'Accessibility on one axis. Enforceable action control on the other.');
  const x0=1.30, y0=5.85, x1=11.95, y1=2.10;
  slide.addShape(pptx.ShapeType.line,{x:x0,y:y0,w:x1-x0,h:0,line:{color:C.slate2,width:1.5,endArrowType:'triangle'}});
  slide.addShape(pptx.ShapeType.line,{x:x0,y:y0,w:0,h:y1-y0,line:{color:C.slate2,width:1.5,endArrowType:'triangle'}});
  slide.addText('MORE ACCESSIBLE TO NON-TECHNICAL BUILDERS',{x:7.55,y:6.08,w:4.35,h:0.20,fontFace:FONT,fontSize:7.3,bold:true,color:C.slate2,align:'right',charSpacing:0.8,margin:0});
  slide.addText('STRONGER ACTION\nBOUNDARIES',{x:0.58,y:2.12,w:1.2,h:0.58,fontFace:FONT,fontSize:7.3,bold:true,color:C.slate2,rotate:270,align:'center',margin:0});
  addCard(slide,2.05,4.55,2.75,0.93,{fill:C.white,line:C.border,shadow:false});
  slide.addText('Developer frameworks',{x:2.30,y:4.82,w:2.25,h:0.22,fontFace:DISPLAY,fontSize:13,bold:true,color:C.ink,align:'center',margin:0});
  addCard(slide,6.50,4.25,2.30,0.85,{fill:C.soft,line:'B7D0F7',shadow:false});
  slide.addText('Visual agent builders',{x:6.68,y:4.50,w:1.94,h:0.22,fontFace:DISPLAY,fontSize:11.8,bold:true,color:C.ink,align:'center',margin:0,fit:'shrink'});
  addCard(slide,2.35,2.65,2.95,0.93,{fill:'F4F6FA',line:C.border,shadow:false});
  slide.addText('Security / identity layers',{x:2.56,y:2.92,w:2.53,h:0.22,fontFace:DISPLAY,fontSize:12.5,bold:true,color:C.ink,align:'center',margin:0});
  slide.addShape(pptx.ShapeType.ellipse,{x:8.86,y:2.25,w:2.05,h:2.05,fill:{color:C.signal,transparency:4},line:{color:C.signal,width:1.3},shadow:safeOuterShadow('0054F3',0.20,45,2.2,1.0)});
  slide.addText('SAURONID',{x:9.17,y:2.80,w:1.43,h:0.22,fontFace:FONT,fontSize:8.4,bold:true,color:C.white,charSpacing:1.1,align:'center',margin:0});
  slide.addText('Accessible creation\n+ enforceable boundaries',{x:9.04,y:3.16,w:1.68,h:0.54,fontFace:DISPLAY,fontSize:11.4,bold:true,color:C.white,align:'center',margin:0,fit:'shrink'});
  addCard(slide,8.20,5.12,3.85,0.62,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('Do not become a generic builder with a security toggle.',{x:8.49,y:5.30,w:3.26,h:0.25,fontFace:FONT,fontSize:9.4,bold:true,color:C.white,align:'center',margin:0,fit:'shrink'});
  addFooter(slide);
}

// 6 - Positioning statement
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '05 / Positioning', true);
  addTitle(slide, 'A precise place in the customer’s mind', 'Creation first. Boundaries native. Technical depth available when needed.', true);
  addCard(slide,0.76,2.05,7.42,3.84,{fill:'071B51',line:'1D4A94',shadow:false});
  slide.addText('For business operators and teams that want AI agents to do real work, SauronID is a platform for building and running agents with explicit intent, capabilities and enforceable boundaries.',{x:1.14,y:2.48,w:6.62,h:1.34,fontFace:DISPLAY,fontSize:23.5,bold:true,color:C.white,margin:0,fit:'shrink'});
  slide.addText('Unlike a generic agent builder or a security layer added after deployment, SauronID makes the boundary part of the agent from the moment it is created.',{x:1.16,y:4.23,w:6.25,h:0.84,fontFace:FONT,fontSize:12.2,color:'BFD8FF',margin:0,fit:'shrink'});
  addPill(slide,'POSITIONING STATEMENT',1.16,5.29,1.82,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  const chips=[['BUILD','a real job'],['CHOOSE','models + tools'],['BOUND','limits + approvals'],['RUN','local now / cloud later']];
  chips.forEach((c,i)=>{
    const y=2.15+i*0.93;
    addCard(slide,8.60,y,3.93,0.72,{fill:i===2?'102F71':'041747',line:'1D4A94',shadow:false});
    slide.addText(c[0],{x:8.87,y:y+0.20,w:0.88,h:0.20,fontFace:MONO,fontSize:8.3,bold:true,color:i===2?C.sky:'6FA9F6',margin:0});
    slide.addText(c[1],{x:9.85,y:y+0.18,w:2.36,h:0.25,fontFace:DISPLAY,fontSize:12.5,bold:true,color:C.white,margin:0,fit:'shrink'});
  });
  addFooter(slide,true);
}

// 7 - ICP
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '06 / Audience');
  addTitle(slide, 'Start with the operator who knows the job', 'The first user is not necessarily technical - but the workflow is real and valuable.');
  addCard(slide,0.70,2.05,4.08,4.08,{fill:C.midnight,line:C.midnight,shadow:false});
  addPill(slide,'PRIMARY USER',1.02,2.38,1.24,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  slide.addText('AI-forward\nbusiness operator',{x:1.02,y:2.94,w:3.15,h:0.98,fontFace:DISPLAY,fontSize:25,bold:true,color:C.white,margin:0});
  addBulletList(slide,['Already uses ChatGPT or Claude','Owns a repeated business workflow','Needs tools and write access','Does not want unrestricted authority'],1.02,4.30,3.15,1.38,true,10.4);
  const roles=[['CHAMPION','Ops / RevOps / Finance Ops'],['VALIDATOR','IT / platform / security'],['BUYER','Functional leader'],['EXPANSION','Team and enterprise admins']];
  roles.forEach((r,i)=>{
    const x=5.16+(i%2)*3.62, y=2.05+Math.floor(i/2)*2.10;
    addCard(slide,x,y,3.26,1.70,{shadow:false,fill:i===0?C.soft:C.white,line:i===0?'B7D0F7':C.border});
    slide.addText(r[0],{x:x+0.22,y:y+0.24,w:1.0,h:0.20,fontFace:MONO,fontSize:8,bold:true,color:C.signal,margin:0});
    slide.addText(r[1],{x:x+0.22,y:y+0.65,w:2.75,h:0.55,fontFace:DISPLAY,fontSize:16,bold:true,color:C.ink,margin:0,fit:'shrink'});
    slide.addText(i===0?'Builds the first useful agent.':i===1?'Verifies runtime and controls.':i===2?'Pays after value is proven.':'Needs shared policies and audit.',{x:x+0.22,y:y+1.24,w:2.76,h:0.26,fontFace:FONT,fontSize:8.7,color:C.slate,margin:0,fit:'shrink'});
  });
  addCard(slide,5.16,6.20,6.88,0.48,{fill:'FFF7E8',line:'F5DDAE',shadow:false});
  slide.addText('Avoid the first wedge: people who refuse agents entirely, or users seeking unrestricted autonomy.',{x:5.42,y:6.34,w:6.37,h:0.18,fontFace:FONT,fontSize:8.8,bold:true,color:'8B5E10',align:'center',margin:0});
  addFooter(slide);
}

// 8 - use cases
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '07 / Initial jobs');
  addTitle(slide, 'Launch with bounded jobs, not “build anything”', 'High-frequency, measurable workflows with visible limits make the value obvious.');
  const useCases = [
    ['Research + CRM','Research accounts, summarize findings and update approved fields.',['Allowed fields','No deletion','Approval before send']],
    ['Support operations','Classify tickets, draft replies and perform reversible actions.',['Customer data scope','Refund threshold','Escalation above limit']],
    ['Finance operations','Reconcile invoices, prepare actions and request approval.',['Approved vendors','Amount cap','Human confirmation']]
  ];
  useCases.forEach((u,i)=>{
    const x=0.72+i*4.12;
    addCard(slide,x,2.08,3.75,4.02,{shadow:false,fill:i===1?'F2F7FF':C.white,line:i===1?'B7D0F7':C.border});
    addIcon(slide,i===0?'intent':i===1?'tools':'approval',x+0.25,2.36,0.54);
    slide.addText(u[0],{x:x+0.96,y:2.41,w:2.42,h:0.30,fontFace:DISPLAY,fontSize:17,bold:true,color:C.ink,margin:0,fit:'shrink'});
    addBody(slide,u[1],x+0.25,3.03,3.12,0.72,false,10.2);
    slide.addText('DEFAULT BOUNDARIES',{x:x+0.25,y:3.95,w:1.55,h:0.18,fontFace:FONT,fontSize:7.6,bold:true,color:C.signal,charSpacing:1.1,margin:0});
    u[2].forEach((b,j)=>{
      slide.addShape(pptx.ShapeType.ellipse,{x:x+0.27,y:4.38+j*0.42,w:0.10,h:0.10,fill:{color:i===2?C.review:C.allowed},line:{color:i===2?C.review:C.allowed}});
      slide.addText(b,{x:x+0.49,y:4.30+j*0.42,w:2.78,h:0.22,fontFace:FONT,fontSize:9.2,color:C.ink,margin:0});
    });
  });
  addCard(slide,2.05,6.28,9.22,0.40,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('Selection rule: frequent + measurable + bounded + reversible or approval-gated + demoable in five minutes.',{x:2.32,y:6.40,w:8.68,h:0.16,fontFace:FONT,fontSize:8.6,bold:true,color:C.white,align:'center',margin:0,fit:'shrink'});
  addFooter(slide);
}

// 9 - product architecture
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '08 / Product architecture', true);
  addTitle(slide, 'One agent. Two ways to run.', 'Early access begins with a guided launcher. Managed cloud execution comes later.', true);
  addCard(slide,0.72,2.04,5.72,3.88,{fill:'071B51',line:'1D4A94',shadow:false});
  addPill(slide,'EARLY ACCESS  /  NOW',1.04,2.36,1.72,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  slide.addText('SauronID Launcher',{x:1.04,y:2.92,w:4.45,h:0.46,fontFace:DISPLAY,fontSize:24,bold:true,color:C.white,margin:0});
  addBulletList(slide,['Downloadable desktop app','Guided setup for non-technical users','Supported local models or your own API key','Local execution free','Hardware and provider limits stated clearly'],1.04,3.67,4.62,1.72,true,10.4);
  addCard(slide,6.88,2.04,5.72,3.88,{fill:'041747',line:'1D4A94',shadow:false});
  addPill(slide,'PLANNED  /  LATER',7.20,2.36,1.48,{dark:true,fill:'14285A',color:'9CBCE7',line:'27477E'});
  slide.addText('SauronID Cloud',{x:7.20,y:2.92,w:4.45,h:0.46,fontFace:DISPLAY,fontSize:24,bold:true,color:C.white,margin:0});
  addBulletList(slide,['Managed execution and model access','No local compute dependency','Scheduled and background runs','Synced agents and collaboration','Subscription, usage or hybrid pricing hypothesis'],7.20,3.67,4.62,1.72,true,10.4);
  lineArrow(slide,5.92,4.00,6.72,4.00,C.sky,2.2,'triangle');
  addCard(slide,3.68,6.20,5.95,0.50,{fill:C.signal,line:C.signal,shadow:false});
  slide.addText('One agent definition  •  one boundary model  •  multiple execution modes',{x:3.93,y:6.35,w:5.45,h:0.18,fontFace:FONT,fontSize:8.8,bold:true,color:C.white,align:'center',margin:0});
  addFooter(slide,true);
  addSources(slide,['Internal: founder-defined early-access and future product direction. Launcher packaging is not yet verified by the uploaded source repository.']);
}

// 10 - product grammar
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '09 / Product grammar');
  addTitle(slide, 'The setup flow should teach the product', 'Five concepts, experienced as one continuous path.');
  const steps=[
    ['01','INTENT','The job to accomplish','intent'],
    ['02','CAPABILITIES','Models, tools, data and actions','tools'],
    ['03','BOUNDARIES','Limits, approvals and stop conditions','bounds'],
    ['04','RUN','Local launcher now; cloud later','run'],
    ['05','PROOF','What happened, stopped and why','proof']
  ];
  steps.forEach((s,i)=>{
    const x=0.55+i*2.52;
    addCard(slide,x,2.30,2.25,3.28,{shadow:false,fill:i===2?'EEF4FF':C.white,line:i===2?'B7D0F7':C.border});
    addIcon(slide,s[3],x+0.22,2.58,0.54,i===2?'0054F3':'2384FB',i===2?'DDEBFF':'EEF4FF');
    slide.addText(s[0],{x:x+1.45,y:2.63,w:0.48,h:0.20,fontFace:MONO,fontSize:8.2,bold:true,color:C.slate2,align:'right',margin:0});
    slide.addText(s[1],{x:x+0.22,y:3.35,w:1.76,h:0.24,fontFace:FONT,fontSize:8.4,bold:true,color:C.signal,charSpacing:1.2,margin:0});
    slide.addText(s[2],{x:x+0.22,y:3.83,w:1.78,h:0.80,fontFace:DISPLAY,fontSize:15.5,bold:true,color:C.ink,margin:0,fit:'shrink'});
    slide.addText(i===0?'What should success look like?':i===1?'What does it need to do the job?':i===2?'What can never happen without permission?':i===3?'Where and when does it execute?':'Can the user understand the decision?',{x:x+0.22,y:4.88,w:1.80,h:0.45,fontFace:FONT,fontSize:8.3,color:C.slate,margin:0,fit:'shrink'});
    if(i<4) lineArrow(slide,x+2.25,3.94,x+2.49,3.94,C.border,1.2,'triangle');
  });
  addCard(slide,2.20,6.10,8.90,0.52,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('The customer should never feel that they are configuring five separate security products.',{x:2.50,y:6.25,w:8.32,h:0.18,fontFace:FONT,fontSize:9.2,bold:true,color:C.white,align:'center',margin:0});
  addFooter(slide);
}

// 11 - moat plain English
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '10 / Product truth');
  addTitle(slide, 'The moat, translated into product behavior', 'The code already supports a serious control foundation. The brand should explain consequences, not jargon.');
  addCard(slide,0.70,2.08,5.30,4.10,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addImage({ path: SCREEN_AGENT, ...imageSizingCrop(SCREEN_AGENT,0.90,2.30,4.90,3.05) });
  slide.addShape(pptx.ShapeType.roundRect,{x:0.90,y:5.56,w:4.90,h:0.36,rectRadius:0.08,fill:{color:'0D2D70'},line:{color:'2055A4'}});
  slide.addText('Current repository: real agent, mandate, status and activity surfaces',{x:1.10,y:5.68,w:4.50,h:0.14,fontFace:FONT,fontSize:7.6,color:C.sky,align:'center',margin:0});
  const truths=[
    ['Owner mandate','A real owner grants the agent a job and authority.'],
    ['Per-action binding','The request cannot change after the agent signs it.'],
    ['Server-side boundaries','The agent cannot rewrite the rules checking its actions.'],
    ['One-use permission','A sensitive permission cannot simply be replayed.'],
    ['Receipts + revocation','See what happened and stop the agent immediately.']
  ];
  truths.forEach((t,i)=>{
    const y=2.13+i*0.79;
    addCard(slide,6.36,y,6.18,0.63,{shadow:false,fill:i===2?'EEF4FF':C.white,line:i===2?'B7D0F7':C.border});
    slide.addText(t[0],{x:6.62,y:y+0.18,w:1.68,h:0.22,fontFace:DISPLAY,fontSize:11.8,bold:true,color:C.ink,margin:0,fit:'shrink'});
    slide.addText(t[1],{x:8.48,y:y+0.15,w:3.70,h:0.28,fontFace:FONT,fontSize:9.2,color:C.slate,margin:0,fit:'shrink'});
  });
  addFooter(slide);
  addSources(slide,['Internal: uploaded SauronID README, dashboard and technical documentation.']);
}

// 12 messaging
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '11 / Messaging', true);
  addTitle(slide, 'Build agents you can actually let act.', 'The headline sells capability. The supporting story makes boundaries concrete.', true);
  addCard(slide,0.74,2.07,7.25,3.87,{fill:'071B51',line:'1D4A94',shadow:false});
  addPill(slide,'MASTER LINE',1.08,2.40,1.22,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  slide.addText('Build agents you can\nactually let act.',{x:1.08,y:2.92,w:5.88,h:1.18,fontFace:DISPLAY,fontSize:30,bold:true,color:C.white,margin:0,fit:'shrink'});
  slide.addText('Give an agent a real job, choose the models and tools it can use, and set the boundaries it cannot cross.',{x:1.10,y:4.44,w:5.82,h:0.72,fontFace:FONT,fontSize:12.2,color:'BFD8FF',margin:0,fit:'shrink'});
  addPill(slide,'THE AGENT PLATFORM WITH BOUNDARIES BUILT IN',1.10,5.36,3.56,{dark:true,fill:'102F71',color:C.sky,line:'2859A5'});
  const ladder=[['01','Outcome','Build a useful agent'],['02','Control','Choose tools and limits'],['03','Access','Start locally'],['04','Evidence','See actions and stops'],['05','Proof','Inspect the architecture']];
  ladder.forEach((l,i)=>{
    const y=2.10+i*0.76;
    slide.addText(l[0],{x:8.45,y:y+0.18,w:0.38,h:0.18,fontFace:MONO,fontSize:7.7,bold:true,color:'6FA9F6',margin:0});
    slide.addText(l[1],{x:8.94,y:y+0.14,w:1.12,h:0.22,fontFace:FONT,fontSize:8.4,bold:true,color:C.sky,margin:0});
    slide.addText(l[2],{x:10.15,y:y+0.12,w:2.17,h:0.26,fontFace:DISPLAY,fontSize:11.7,bold:true,color:C.white,margin:0,fit:'shrink'});
    if(i<4) slide.addShape(pptx.ShapeType.line,{x:8.63,y:y+0.42,w:0,h:0.30,line:{color:'23549E',width:1.2}});
  });
  addFooter(slide,true);
}

// 13 copy do/dont
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '12 / Copy');
  addTitle(slide, 'Explain control in the language of consequences', 'Creation-first, calm, specific and honest about availability.');
  addCard(slide,0.72,2.10,5.72,3.95,{fill:C.allowedSoft,line:'B7E5DA',shadow:false});
  slide.addText('SOUND LIKE',{x:1.02,y:2.42,w:1.12,h:0.20,fontFace:FONT,fontSize:8.3,bold:true,color:C.allowed,charSpacing:1.3,margin:0});
  const good=[
    'Choose the tools this agent can use.',
    'Require approval above EUR500.',
    'Stopped: destination outside the approved list.',
    'Start locally with a supported model or your own API key.'
  ];
  good.forEach((t,i)=>{
    slide.addShape(pptx.ShapeType.ellipse,{x:1.03,y:2.94+i*0.63,w:0.13,h:0.13,fill:{color:C.allowed},line:{color:C.allowed}});
    slide.addText(t,{x:1.34,y:2.86+i*0.63,w:4.45,h:0.34,fontFace:DISPLAY,fontSize:13,bold:true,color:C.ink,margin:0,fit:'shrink'});
  });
  addCard(slide,6.82,2.10,5.78,3.95,{fill:C.stoppedSoft,line:'F6CCD4',shadow:false});
  slide.addText('NEVER SOUND LIKE',{x:7.14,y:2.42,w:1.55,h:0.20,fontFace:FONT,fontSize:8.3,bold:true,color:C.stopped,charSpacing:1.3,margin:0});
  const bad=[
    'Military-grade autonomous agent security.',
    'Provision a least-privilege capability envelope.',
    'Threat neutralized.',
    'Run any model, anywhere, for free.'
  ];
  bad.forEach((t,i)=>{
    slide.addShape(pptx.ShapeType.line,{x:7.16,y:2.94+i*0.63,w:0.13,h:0.13,line:{color:C.stopped,width:2.0,beginArrowType:'none',endArrowType:'none'}});
    slide.addText(t,{x:7.45,y:2.86+i*0.63,w:4.53,h:0.34,fontFace:DISPLAY,fontSize:13,bold:true,color:C.ink,margin:0,fit:'shrink'});
  });
  addCard(slide,2.48,6.28,8.38,0.40,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('Progressively disclose technical terms: job → boundary → mandate → signature → proof.',{x:2.75,y:6.40,w:7.84,h:0.16,fontFace:FONT,fontSize:8.8,bold:true,color:C.white,align:'center',margin:0});
  addFooter(slide);
}

// 14 Everyone can cook
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '13 / Community voice');
  addTitle(slide, '“Everyone can cook” is a movement, not the proposition', 'Use it to invite creators in - not to explain the whole company.');
  addCard(slide,0.72,2.04,7.05,4.10,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('Everyone\ncan cook.',{x:1.12,y:2.57,w:5.60,h:1.34,fontFace:DISPLAY,fontSize:38,bold:true,color:C.white,margin:0});
  slide.addText('A community line for learning, templates, launches and creator stories.',{x:1.14,y:4.34,w:5.65,h:0.72,fontFace:FONT,fontSize:12.3,color:'BFD8FF',margin:0,fit:'shrink'});
  addPill(slide,'SECONDARY  /  SELECTIVE',1.14,5.39,1.87,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  addCard(slide,8.10,2.04,4.48,1.80,{shadow:false,fill:C.white,line:C.border});
  slide.addText('USE FOR',{x:8.40,y:2.34,w:0.90,h:0.18,fontFace:FONT,fontSize:8,bold:true,color:C.signal,charSpacing:1.1,margin:0});
  addBulletList(slide,['Creator program','Template gallery','Onboarding moments','Community stories'],8.40,2.77,3.52,0.80,false,9.8);
  addCard(slide,8.10,4.18,4.48,1.96,{shadow:false,fill:'FFF7E8',line:'F5DDAE'});
  slide.addText('DO NOT',{x:8.40,y:4.48,w:0.90,h:0.18,fontFace:FONT,fontSize:8,bold:true,color:C.review,charSpacing:1.1,margin:0});
  addBulletList(slide,['Use it as the only hero line','Turn every concept into food metaphors','Reduce B2B credibility','Make the UI playful during sensitive actions'],8.40,4.91,3.58,0.92,false,9.4,'7D5A17');
  addFooter(slide);
}

// 15 Logo meaning
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '14 / Logo');
  addTitle(slide, 'The eye becomes a symbol of agency with oversight', 'Focus and visibility - not surveillance, omniscience or fear.');
  slide.addImage({ path: LOGO, ...imageSizingContain(LOGO,0.78,2.00,4.40,4.40) });
  const meanings=[
    ['Eye','A clear view of what the agent is doing.'],
    ['White aperture','The human objective at the center.'],
    ['Orbiting ribbons','Models, tools and data on one controlled path.'],
    ['Light / dark','Freedom to act balanced by visible limits.']
  ];
  meanings.forEach((m,i)=>{
    const x=5.65+(i%2)*3.45, y=2.15+Math.floor(i/2)*1.90;
    addCard(slide,x,y,3.10,1.50,{shadow:false,fill:i===0?C.soft:C.white,line:i===0?'B7D0F7':C.border});
    slide.addShape(pptx.ShapeType.ellipse,{x:x+0.24,y:y+0.25,w:0.16,h:0.16,fill:{color:i===3?C.sky:C.signal},line:{color:i===3?C.sky:C.signal}});
    addCardTitle(slide,m[0],x+0.58,y+0.20,2.20,false,14.0);
    addBody(slide,m[1],x+0.24,y+0.72,2.58,0.50,false,9.2);
  });
  addCard(slide,5.65,6.06,6.55,0.52,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('Rule: one meaningful logo-derived moment per composition. Never repeat the eye as decoration.',{x:5.94,y:6.22,w:5.96,h:0.18,fontFace:FONT,fontSize:8.5,bold:true,color:C.white,align:'center',margin:0,fit:'shrink'});
  addFooter(slide);
}

// 16 Color
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '15 / Color');
  addTitle(slide, 'Light-first product. Deep-navy proof moments.', 'The palette stays. Its proportion changes to feel more accessible and creator-led.');
  const colors=[
    ['MIDNIGHT 950','000D35','Proof / focus'],['NAVY 900','000F3B','Dark UI'],['SIGNAL 600','0054F3','Primary action'],['ORBIT 500','2384FB','Progress'],['SKY 300','78C6FB','Highlight'],['CLOUD 50','F7FAFF','Canvas']
  ];
  colors.forEach((c,i)=>{
    const x=0.72+i*2.05;
    slide.addShape(pptx.ShapeType.roundRect,{x,y:2.12,w:1.80,h:2.32,rectRadius:0.14,fill:{color:c[1]},line:{color:i===5?C.border:c[1],width:0.8}});
    slide.addText(c[0],{x:x+0.12,y:4.65,w:1.55,h:0.17,fontFace:FONT,fontSize:6.8,bold:true,color:C.ink,align:'center',margin:0,fit:'shrink'});
    slide.addText(`#${c[1]}`,{x:x+0.12,y:4.94,w:1.55,h:0.17,fontFace:MONO,fontSize:7.3,color:C.slate,align:'center',margin:0});
    slide.addText(c[2],{x:x+0.12,y:5.22,w:1.55,h:0.17,fontFace:FONT,fontSize:7.0,color:C.slate2,align:'center',margin:0});
  });
  const states=[['Allowed',C.allowed,C.allowedSoft],['Needs approval',C.review,C.reviewSoft],['Stopped',C.stopped,C.stoppedSoft],['Running',C.running,C.runningSoft]];
  states.forEach((s,i)=>{
    const x=2.30+i*2.30;
    addPill(slide,s[0],x,5.88,1.90,{fill:s[2],color:s[1],line:s[2],fontSize:8.2});
  });
  slide.addText('Semantic colors explain action state. They are not decorative brand accents.',{x:2.25,y:6.42,w:8.90,h:0.18,fontFace:FONT,fontSize:8.4,color:C.slate,align:'center',margin:0});
  addFooter(slide);
}

// 17 typography
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '16 / Typography', true);
  addTitle(slide, 'Direct type. Distinctive composition.', 'Warm enough for builders; precise enough for technical proof.', true);
  slide.addText('Inter Tight',{x:0.78,y:2.14,w:5.20,h:0.52,fontFace:DISPLAY,fontSize:30,bold:true,color:C.white,margin:0});
  slide.addText('Display / recommended',{x:0.80,y:2.74,w:2.65,h:0.20,fontFace:FONT,fontSize:8.2,bold:true,color:C.sky,charSpacing:1.1,margin:0});
  slide.addText('Build agents you can\nactually let act.',{x:0.78,y:3.30,w:5.25,h:1.34,fontFace:DISPLAY,fontSize:31,bold:true,color:'BFD8FF',margin:0});
  slide.addText('Inter',{x:0.80,y:5.12,w:1.05,h:0.32,fontFace:FONT,fontSize:18,bold:true,color:C.white,margin:0});
  slide.addText('UI, body and product guidance',{x:2.35,y:5.17,w:2.65,h:0.20,fontFace:FONT,fontSize:8.8,color:'95B7E9',margin:0});
  addCard(slide,6.60,2.12,5.92,3.95,{fill:'071B51',line:'1D4A94',shadow:false});
  slide.addText('IBM PLEX MONO',{x:6.96,y:2.47,w:2.10,h:0.20,fontFace:MONO,fontSize:9,bold:true,color:C.sky,charSpacing:1.2,margin:0});
  const rows=[['intent','Update approved CRM fields'],['boundary','No delete · approval before send'],['status','STOPPED'],['reason','destination_not_allowed']];
  rows.forEach((r,i)=>{
    const y=3.04+i*0.60;
    slide.addText(r[0].toUpperCase(),{x:6.96,y,w:1.22,h:0.18,fontFace:MONO,fontSize:7.8,bold:true,color:'6FA9F6',margin:0});
    slide.addText(r[1],{x:8.30,y,w:3.60,h:0.22,fontFace:MONO,fontSize:9.2,color:i===2?'F29AB1':'D6E7FF',margin:0,fit:'shrink'});
  });
  addPill(slide,'MONO = EVIDENCE, NOT ATMOSPHERE',6.96,5.51,2.72,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  addFooter(slide,true);
}

// 18 visual grammar
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '17 / Visual grammar');
  addTitle(slide, 'Five motifs. One rule: clarity first.', 'The logo informs the system without turning the product into a themed interface.');
  const motifs=[
    ['Canvas','Generous light space makes creation feel possible.','FFFFFF'],
    ['Boundary','A frame, rail or range shows what applies.','EEF4FF'],
    ['Path','A route connects intent, tools, approvals and result.','EAF8F5'],
    ['Checkpoint','A visible pause for review, approval or stop.','FFF7E8'],
    ['Orbit','One curve may connect models, tools and data.','F1EFFF']
  ];
  motifs.forEach((m,i)=>{
    const x=0.50+i*2.52;
    addCard(slide,x,2.17,2.24,3.52,{shadow:false,fill:m[2],line:i===0?C.border:m[2]});
    if(i===0){ slide.addShape(pptx.ShapeType.ellipse,{x:x+0.48,y:2.55,w:1.28,h:0.84,fill:{color:C.white},line:{color:C.signal,width:1.2}}); }
    if(i===1){ slide.addShape(pptx.ShapeType.roundRect,{x:x+0.45,y:2.48,w:1.35,h:1.00,rectRadius:0.18,fill:{color:C.white},line:{color:C.signal,width:2.0}}); }
    if(i===2){ lineArrow(slide,x+0.45,3.05,x+1.75,3.05,C.allowed,3.0,'triangle'); }
    if(i===3){ slide.addShape(pptx.ShapeType.line,{x:x+0.46,y:3.05,w:1.30,h:0,line:{color:C.review,width:3.0}}); slide.addShape(pptx.ShapeType.ellipse,{x:x+1.03,y:2.80,w:0.50,h:0.50,fill:{color:C.review},line:{color:C.review}}); }
    if(i===4){ slide.addShape(pptx.ShapeType.arc,{x:x+0.43,y:2.50,w:1.43,h:1.00,adjustPoint:0.25,rotate:8,fill:{color:'F1EFFF',transparency:100},line:{color:C.running,width:3.0}}); }
    slide.addText(m[0],{x:x+0.22,y:3.85,w:1.80,h:0.28,fontFace:DISPLAY,fontSize:15.2,bold:true,color:C.ink,align:'center',margin:0});
    slide.addText(m[1],{x:x+0.20,y:4.36,w:1.84,h:0.80,fontFace:FONT,fontSize:8.8,color:C.slate,align:'center',margin:0,fit:'shrink'});
  });
  addCard(slide,1.48,6.13,10.38,0.48,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('If it looks more “cyber” but does not make the product easier to understand, remove it.',{x:1.78,y:6.28,w:9.78,h:0.18,fontFace:FONT,fontSize:9.2,bold:true,color:C.white,align:'center',margin:0});
  addFooter(slide);
}

// 19 Launcher UX
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '18 / Launcher UX');
  addTitle(slide, 'The launcher is the adoption strategy', 'It must turn infrastructure choices into a guided path to a useful first run.');
  // window
  slide.addShape(pptx.ShapeType.roundRect,{x:0.70,y:2.03,w:7.10,h:4.25,rectRadius:0.20,fill:{color:C.white},line:{color:'B7D0F7',width:1.1},shadow:safeOuterShadow('000D35',0.14,45,2.3,1.1)});
  slide.addShape(pptx.ShapeType.rect,{x:0.70,y:2.03,w:7.10,h:0.43,fill:{color:C.soft},line:{color:C.soft}});
  ['D94C64','D69020','0C9B8E'].forEach((c,i)=>slide.addShape(pptx.ShapeType.ellipse,{x:0.94+i*0.22,y:2.20,w:0.10,h:0.10,fill:{color:c},line:{color:c}}));
  addLogoLockup(slide,1.02,2.68,0.66,false);
  slide.addText('Create your first agent',{x:1.02,y:3.44,w:3.55,h:0.34,fontFace:DISPLAY,fontSize:19,bold:true,color:C.ink,margin:0});
  slide.addText('What job should it do?',{x:1.03,y:3.96,w:2.35,h:0.20,fontFace:FONT,fontSize:9.3,bold:true,color:C.slate,margin:0});
  addCard(slide,1.02,4.29,5.97,0.66,{shadow:false,fill:C.cloud,line:C.border});
  slide.addText('Research new accounts and update approved CRM fields',{x:1.28,y:4.52,w:5.46,h:0.21,fontFace:FONT,fontSize:10.2,color:C.ink,margin:0});
  const chips=[['Model','Your API key'],['Tools','Web + CRM'],['Boundary','Approval before send']];
  chips.forEach((c,i)=>{
    const x=1.02+i*1.84;
    addCard(slide,x,5.20,1.62,0.68,{shadow:false,fill:i===2?C.reviewSoft:C.soft,line:i===2?'F5DDAE':'B7D0F7'});
    slide.addText(c[0].toUpperCase(),{x:x+0.14,y:5.34,w:0.70,h:0.14,fontFace:MONO,fontSize:6.5,bold:true,color:i===2?C.review:C.signal,margin:0});
    slide.addText(c[1],{x:x+0.14,y:5.58,w:1.34,h:0.18,fontFace:FONT,fontSize:7.6,bold:true,color:C.ink,margin:0,fit:'shrink'});
  });
  slide.addShape(pptx.ShapeType.roundRect,{x:6.48,y:5.20,w:0.68,h:0.68,rectRadius:0.12,fill:{color:C.signal},line:{color:C.signal}});
  slide.addText('Test',{x:6.54,y:5.45,w:0.56,h:0.16,fontFace:FONT,fontSize:8.4,bold:true,color:C.white,align:'center',margin:0});
  const ux=[
    ['Outcome first','Ask for the job before model or policy.'],
    ['Template first','Avoid the blank-canvas trap.'],
    ['Progressive detail','Simple defaults; advanced controls available.'],
    ['Teach by contrast','Run one allowed and one stopped action.'],
    ['Explain every stop','Show the rule and next step.']
  ];
  ux.forEach((u,i)=>{
    const y=2.08+i*0.83;
    slide.addText(`0${i+1}`,{x:8.35,y:y+0.18,w:0.42,h:0.18,fontFace:MONO,fontSize:7.8,bold:true,color:C.signal,margin:0});
    slide.addText(u[0],{x:8.89,y:y+0.12,w:1.67,h:0.24,fontFace:DISPLAY,fontSize:12.5,bold:true,color:C.ink,margin:0});
    slide.addText(u[1],{x:10.64,y:y+0.10,w:1.80,h:0.33,fontFace:FONT,fontSize:8.4,color:C.slate,margin:0,fit:'shrink'});
  });
  addFooter(slide);
}

// 20 Website direction
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '19 / Website', true);
  addTitle(slide, 'A product page for builders, with proof behind it', 'Outcome → setup → bounded action → launcher → future cloud → technical proof.', true);
  slide.addShape(pptx.ShapeType.roundRect,{x:0.69,y:2.02,w:11.96,h:4.40,rectRadius:0.18,fill:{color:C.cloud},line:{color:'2A60B4',width:1.2},shadow:safeOuterShadow('000000',0.28,45,3,1.5)});
  slide.addShape(pptx.ShapeType.rect,{x:0.69,y:2.02,w:11.96,h:0.43,fill:{color:C.white},line:{color:C.white}});
  ['D94C64','D69020','0C9B8E'].forEach((c,i)=>slide.addShape(pptx.ShapeType.ellipse,{x:0.94+i*0.22,y:2.18,w:0.10,h:0.10,fill:{color:c},line:{color:c}}));
  addLogoLockup(slide,0.98,2.65,0.68,false);
  slide.addText('Product     How it works     Templates     Technical',{x:7.05,y:2.82,w:3.45,h:0.18,fontFace:FONT,fontSize:8.2,bold:true,color:C.slate,align:'right',margin:0});
  slide.addShape(pptx.ShapeType.roundRect,{x:10.78,y:2.63,w:1.28,h:0.40,rectRadius:0.10,fill:{color:C.signal},line:{color:C.signal}});
  slide.addText('Join early access',{x:10.91,y:2.75,w:1.02,h:0.16,fontFace:FONT,fontSize:7.3,bold:true,color:C.white,align:'center',margin:0,fit:'shrink'});
  slide.addText('Build agents you can\nactually let act.',{x:1.02,y:3.48,w:5.42,h:1.00,fontFace:DISPLAY,fontSize:30,bold:true,color:C.ink,margin:0});
  slide.addText('Give an agent a real job, choose its models and tools, and set the boundaries it cannot cross.',{x:1.05,y:4.73,w:4.93,h:0.63,fontFace:FONT,fontSize:10.8,color:C.slate,margin:0,fit:'shrink'});
  slide.addShape(pptx.ShapeType.roundRect,{x:1.04,y:5.58,w:1.62,h:0.45,rectRadius:0.11,fill:{color:C.signal},line:{color:C.signal}});
  slide.addText('Join early access',{x:1.16,y:5.72,w:1.38,h:0.16,fontFace:FONT,fontSize:8.1,bold:true,color:C.white,align:'center',margin:0});
  slide.addShape(pptx.ShapeType.roundRect,{x:2.84,y:5.58,w:1.72,h:0.45,rectRadius:0.11,fill:{color:C.white},line:{color:'A7BAD8'}});
  slide.addText('See boundaries work',{x:2.98,y:5.72,w:1.44,h:0.16,fontFace:FONT,fontSize:7.9,bold:true,color:C.ink,align:'center',margin:0,fit:'shrink'});
  // mock agent card
  addCard(slide,6.62,3.35,5.22,2.75,{fill:C.white,line:C.border,shadow:false});
  slide.addText('Research account agent',{x:6.94,y:3.67,w:2.80,h:0.30,fontFace:DISPLAY,fontSize:16,bold:true,color:C.ink,margin:0});
  addStatus(slide,'RUNNING',10.42,3.63,'running',1.05);
  const flow=[['1','Research company','allowed'],['2','Update CRM fields','allowed'],['3','Send email','review']];
  flow.forEach((f,i)=>{
    const y=4.22+i*0.52;
    slide.addShape(pptx.ShapeType.ellipse,{x:6.95,y:y+0.02,w:0.22,h:0.22,fill:{color:f[2]==='allowed'?C.allowed:C.review},line:{color:f[2]==='allowed'?C.allowed:C.review}});
    slide.addText(f[0],{x:7.00,y:y+0.055,w:0.12,h:0.12,fontFace:FONT,fontSize:6.5,bold:true,color:C.white,align:'center',margin:0});
    slide.addText(f[1],{x:7.34,y,w:2.15,h:0.22,fontFace:FONT,fontSize:9.0,bold:true,color:C.ink,margin:0,fit:'shrink'});
    addStatus(slide,f[2]==='allowed'?'ALLOWED':'NEEDS APPROVAL',10.02,y-0.02,f[2],1.55);
  });
  addFooter(slide,true);
}

// 21 GTM loop
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '20 / Adoption loop');
  addTitle(slide, 'The first “aha” is an allowed action beside a stopped one', 'Acquisition comes from usefulness. Retention comes from repeated bounded work.');
  const nodes=[
    ['1','Download','Launcher'],['2','Choose','Template'],['3','Connect','Model'],['4','Define','Boundaries'],['5','Run','Useful job'],['6','See','Allowed + stopped'],['7','Reuse','Weekly'],['8','Share','Team']
  ];
  const center={x:6.66,y:4.54};
  nodes.forEach((n,i)=>{
    const ang=(-90+i*45)*Math.PI/180;
    const x=center.x+4.05*Math.cos(ang)-0.80;
    const y=center.y+2.08*Math.sin(ang)-0.46;
    addCard(slide,x,y,1.60,0.92,{shadow:false,fill:i===5?C.reviewSoft:(i===7?C.soft:C.white),line:i===5?'F5DDAE':(i===7?'B7D0F7':C.border)});
    slide.addText(n[0],{x:x+0.12,y:y+0.12,w:0.28,h:0.17,fontFace:MONO,fontSize:7.5,bold:true,color:C.signal,margin:0});
    slide.addText(n[1],{x:x+0.43,y:y+0.10,w:0.98,h:0.20,fontFace:DISPLAY,fontSize:10.6,bold:true,color:C.ink,margin:0,fit:'shrink'});
    slide.addText(n[2],{x:x+0.16,y:y+0.52,w:1.26,h:0.18,fontFace:FONT,fontSize:7.4,color:C.slate,align:'center',margin:0});
  });
  slide.addShape(pptx.ShapeType.ellipse,{x:5.18,y:3.06,w:2.96,h:2.96,fill:{color:C.midnight},line:{color:C.signal,width:1.4},shadow:safeOuterShadow('000D35',0.15,45,2.4,1.0)});
  slide.addText('NORTH STAR',{x:5.80,y:3.80,w:1.72,h:0.20,fontFace:FONT,fontSize:8,bold:true,color:C.sky,charSpacing:1.2,align:'center',margin:0});
  slide.addText('Weekly active\nbounded agents',{x:5.53,y:4.24,w:2.28,h:0.70,fontFace:DISPLAY,fontSize:19,bold:true,color:C.white,align:'center',margin:0});
  slide.addText('Not agents created. Agents doing recurring useful work under active limits.',{x:5.49,y:5.15,w:2.36,h:0.42,fontFace:FONT,fontSize:8.2,color:'BFD8FF',align:'center',margin:0,fit:'shrink'});
  addFooter(slide);
}

// 22 packaging
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '21 / Packaging');
  addTitle(slide, 'Price the execution and teamwork - not the right to learn', 'Packaging remains a hypothesis until usage and willingness to pay are observed.');
  const tiers=[
    ['LOCAL FREE','Launcher','Local / BYOK','Single user','Core boundaries','Community templates'],
    ['CLOUD PRO','Future','Hosted runtime','Schedules + sync','More connectors','Subscription / usage'],
    ['TEAM','Future','Shared workspace','Approvals + secrets','Roles + audit','Team value'],
    ['ENTERPRISE','Future','SSO + SIEM','Private options','Policy admin','SLA + verified compliance']
  ];
  tiers.forEach((t,i)=>{
    const x=0.55+i*3.14;
    addCard(slide,x,2.12,2.82,3.98,{shadow:false,fill:i===0?C.midnight:(i===1?C.soft:C.white),line:i===0?C.midnight:(i===1?'B7D0F7':C.border)});
    slide.addText(t[0],{x:x+0.22,y:2.44,w:2.38,h:0.22,fontFace:FONT,fontSize:8.2,bold:true,color:i===0?C.sky:C.signal,charSpacing:1.2,margin:0});
    slide.addText(t[1],{x:x+0.22,y:2.88,w:2.38,h:0.32,fontFace:DISPLAY,fontSize:18,bold:true,color:i===0?C.white:C.ink,margin:0});
    t.slice(2).forEach((v,j)=>{
      slide.addShape(pptx.ShapeType.ellipse,{x:x+0.25,y:3.55+j*0.52,w:0.11,h:0.11,fill:{color:i===0?C.sky:C.allowed},line:{color:i===0?C.sky:C.allowed}});
      slide.addText(v,{x:x+0.50,y:3.46+j*0.52,w:1.96,h:0.25,fontFace:FONT,fontSize:9.0,color:i===0?'D6E7FF':C.ink,margin:0,fit:'shrink'});
    });
  });
  addCard(slide,2.62,6.29,8.10,0.39,{fill:'FFF7E8',line:'F5DDAE',shadow:false});
  slide.addText('Do not publish pricing before local retention, cloud cost and willingness-to-pay are measured.',{x:2.88,y:6.41,w:7.58,h:0.16,fontFace:FONT,fontSize:8.6,bold:true,color:'8B5E10',align:'center',margin:0});
  addFooter(slide);
}

// 23 claims governance
{
  const slide = pptx.addSlide('DARK');
  addSectionLabel(slide, '22 / Claims governance', true);
  addTitle(slide, 'Separate what exists, what is launching and what is imagined', 'Product truth is part of the brand.', true);
  const labels=[
    ['AVAILABLE NOW',C.allowed,'Verified in the released product.'],
    ['EARLY ACCESS',C.signal,'Packaged product being tested.'],
    ['COMING LATER',C.review,'Planned; no availability promise.'],
    ['EXPLORING',C.running,'Commercial or product hypothesis.']
  ];
  labels.forEach((l,i)=>{
    const y=2.15+i*0.87;
    addCard(slide,0.78,y,4.28,0.66,{fill:'071B51',line:'1D4A94',shadow:false});
    slide.addShape(pptx.ShapeType.ellipse,{x:1.05,y:y+0.22,w:0.18,h:0.18,fill:{color:l[1]},line:{color:l[1]}});
    slide.addText(l[0],{x:1.42,y:y+0.17,w:1.40,h:0.20,fontFace:FONT,fontSize:8.3,bold:true,color:C.white,charSpacing:1.0,margin:0});
    slide.addText(l[2],{x:2.96,y:y+0.14,w:1.74,h:0.26,fontFace:FONT,fontSize:8.2,color:'BFD8FF',margin:0,fit:'shrink'});
  });
  addCard(slide,5.48,2.15,7.05,3.73,{fill:'041747',line:'1D4A94',shadow:false});
  slide.addText('CLAIM CHAIN',{x:5.82,y:2.49,w:1.40,h:0.20,fontFace:FONT,fontSize:8.3,bold:true,color:C.sky,charSpacing:1.3,margin:0});
  const chain=[['OUTCOME','What the user gets'],['MECHANISM','What creates the result'],['EVIDENCE','What can be checked'],['LIMITATION','Where the claim stops']];
  chain.forEach((c,i)=>{
    const x=5.82+i*1.60;
    addCard(slide,x,3.13,1.42,1.63,{fill:i===3?'351A2A':'0D2D70',line:i===3?'6F3156':'2055A4',shadow:false});
    slide.addText(c[0],{x:x+0.12,y:3.43,w:1.18,h:0.18,fontFace:FONT,fontSize:7.4,bold:true,color:i===3?'F29AB1':C.sky,align:'center',margin:0});
    slide.addText(c[1],{x:x+0.13,y:3.89,w:1.16,h:0.48,fontFace:DISPLAY,fontSize:10.5,bold:true,color:C.white,align:'center',margin:0,fit:'shrink'});
    if(i<3) lineArrow(slide,x+1.42,3.95,x+1.56,3.95,'4D78BB',1.3,'triangle');
  });
  slide.addText('Example: protected actions are checked before they reach the connected service - if the deployment prevents bypass of the protected path.',{x:5.82,y:5.12,w:6.15,h:0.43,fontFace:FONT,fontSize:8.8,color:'BFD8FF',align:'center',margin:0,fit:'shrink'});
  addFooter(slide,true);
}

// 24 brand governance close
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '23 / Governance');
  addTitle(slide, 'Make agency feel possible. Make boundaries feel natural.', 'The brand succeeds when capability and control are understood in the same glance.');
  addCard(slide,0.72,2.02,7.10,4.02,{shadow:false});
  slide.addText('BEFORE PUBLISHING',{x:1.04,y:2.35,w:1.90,h:0.20,fontFace:FONT,fontSize:8.4,bold:true,color:C.signal,charSpacing:1.3,margin:0});
  const checks=[
    'Verify every availability claim against the product truth file.',
    'Confirm launcher operating systems, model support and key storage.',
    'Keep cloud, pricing and enterprise capabilities clearly labeled.',
    'Test the first run with non-technical users, not only developers.',
    'Keep technical proof available without making it the homepage.',
    'Check contrast, focus, reduced motion and responsive behavior.'
  ];
  checks.forEach((t,i)=>{
    slide.addShape(pptx.ShapeType.ellipse,{x:1.05,y:2.89+i*0.46,w:0.13,h:0.13,fill:{color:C.allowed},line:{color:C.allowed}});
    slide.addText(t,{x:1.35,y:2.81+i*0.46,w:5.85,h:0.26,fontFace:FONT,fontSize:9.4,color:C.ink,margin:0,fit:'shrink'});
  });
  addCard(slide,8.14,2.02,4.48,4.02,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('FINAL TEST',{x:8.49,y:2.36,w:1.20,h:0.20,fontFace:FONT,fontSize:8.4,bold:true,color:C.sky,charSpacing:1.3,margin:0});
  slide.addText('Does this make the customer want to build - and understand why they can trust the boundary?',{x:8.48,y:2.96,w:3.50,h:1.52,fontFace:DISPLAY,fontSize:23.5,bold:true,color:C.white,margin:0,fit:'shrink'});
  slide.addText('If it only communicates danger, it is the old brand. If it only communicates creation, it loses the moat.',{x:8.50,y:4.78,w:3.42,h:0.78,fontFace:FONT,fontSize:10.8,color:'BFD8FF',margin:0,fit:'shrink'});
  addPill(slide,'BUILD + BOUND',8.50,5.61,1.46,{dark:true,fill:'0D2D70',color:C.sky,line:'2055A4'});
  addLogoLockup(slide,0.72,6.30,0.70,false);
  slide.addText('Brand system v2.0',{x:10.05,y:6.52,w:2.50,h:0.20,fontFace:FONT,fontSize:8.8,color:C.slate,align:'right',margin:0});
  addFooter(slide);
}

// 25 sources and methodology
{
  const slide = pptx.addSlide('LIGHT');
  addSectionLabel(slide, '24 / Sources');
  addTitle(slide, 'Research base and claim scope', 'Market evidence informs the strategy; the uploaded repository defines product truth.');
  addCard(slide,0.72,2.04,5.72,3.98,{shadow:false,fill:C.white,line:C.border});
  slide.addText('PRODUCT SOURCES',{x:1.04,y:2.37,w:1.75,h:0.20,fontFace:FONT,fontSize:8.4,bold:true,color:C.signal,charSpacing:1.2,margin:0});
  addBulletList(slide,[
    'Uploaded SauronID source release and README',
    'Dashboard, policy, threat-model and operations docs',
    'Existing brand book and logo assets',
    'Founder-defined launcher and cloud direction'
  ],1.04,2.86,4.75,1.42,false,10.3,C.ink);
  slide.addText('Important: the launcher and cloud packaging are strategic direction unless explicitly verified in a release.',{x:1.04,y:4.80,w:4.75,h:0.60,fontFace:FONT,fontSize:9.4,bold:true,color:C.stopped,margin:0,fit:'shrink'});
  addCard(slide,6.84,2.04,5.76,3.98,{shadow:false,fill:C.soft,line:'B7D0F7'});
  slide.addText('MARKET SOURCES',{x:7.17,y:2.37,w:1.75,h:0.20,fontFace:FONT,fontSize:8.4,bold:true,color:C.signal,charSpacing:1.2,margin:0});
  addBulletList(slide,[
    'n8n company and funding announcement',
    'Dify company, onboarding and Kakaku case study',
    'TechCrunch reporting on Gumloop and Relevance AI',
    'LM Studio product and offline documentation',
    'Auth0 agent identity product messaging'
  ],7.17,2.86,4.78,1.78,false,9.8,C.ink);
  slide.addText('Company-reported adoption metrics are directional signals, not audited market measurements.',{x:7.17,y:5.00,w:4.72,h:0.52,fontFace:FONT,fontSize:9.2,bold:true,color:'8B5E10',margin:0,fit:'shrink'});
  addCard(slide,2.08,6.28,9.18,0.40,{fill:C.midnight,line:C.midnight,shadow:false});
  slide.addText('The market strategy should be updated after early-access retention and workflow data exist.',{x:2.36,y:6.40,w:8.64,h:0.16,fontFace:FONT,fontSize:8.8,bold:true,color:C.white,align:'center',margin:0});
  addFooter(slide);
  addSources(slide,[
    'https://blog.n8n.io/series-b/',
    'https://dify.ai/about-us',
    'https://dify.ai/ko/blog/try-openai-claude-gemini-grok-free-on-dify-cloud',
    'https://dify.ai/blog/kakaku-accelerates-ai-adoption-with-dify-fast-secure-and-scalable',
    'https://techcrunch.com/2026/03/12/gumloop-lands-50m-from-benchmark-to-turn-every-employee-into-an-ai-agent-builder/',
    'https://techcrunch.com/2025/05/06/relevance-ai-raises-24m-series-b-to-help-anyone-build-teams-of-ai-agents/',
    'https://www.lmstudio.ai/',
    'https://auth0.com/ai'
  ]);
}

for (const slide of pptx._slides) {
  warnIfSlideHasOverlaps(slide, pptx);
  warnIfSlideElementsOutOfBounds(slide, pptx);
}

(async () => {
  await pptx.writeFile({ fileName: '/mnt/data/sauronid_brand_v2_work/build/SauronID_Brand_Book_v2.pptx' });
})();
