/**
 * CV RESULTS PAGE — results.js
 * CVision | Student / Recent Graduate
 */

'use strict';

// ─── State ───────────────────────────────────────────────────
let skillsChartInstance      = null;
let categoryChartInstance    = null;
let jobComparisonChartInstance = null;
let globalSkillsData         = [];
let globalResultsData        = null;
let lastJobResult            = null; // stores full API response after job analysis

// ─── Colour maps ─────────────────────────────────────────────
const CAT_COLORS = {
    'Technical Skills': 'rgba(107,163,213,0.85)',
    'Soft Skills':      'rgba(76,175,80,0.85)',
    'Business Skills':  'rgba(255,193,7,0.85)',
    'Domain Skills':    'rgba(156,39,176,0.85)',
    'Language Skills':  'rgba(33,150,243,0.85)',
    'Other Skills':     'rgba(158,158,158,0.85)'
};
const CAT_KEY_MAP = {
    technical: 'Technical Skills',
    soft:      'Soft Skills',
    business:  'Business Skills',
    domain:    'Domain Skills',
    language:  'Language Skills',
    other:     'Other Skills'
};

// ─── Bloom's taxonomy data ────────────────────────────────────
const BLOOMS_LEVELS = [
    { level: 1, name: 'Remember',   range: '1–2', color: '#ef4444', bg: '#fef2f2',
      desc: 'Recall facts, basic concepts, and information from memory.',
      verbs: 'Define, list, recall, recognise, state, identify',
      cvSignal: 'Skill is mentioned but with no concrete examples or context.' },
    { level: 2, name: 'Understand', range: '3–4', color: '#f59e0b', bg: '#fffbeb',
      desc: 'Explain ideas or concepts, interpret information, and summarise.',
      verbs: 'Explain, summarise, interpret, classify, describe, discuss',
      cvSignal: 'Skill described in a module, course, or brief project with some context.' },
    { level: 3, name: 'Apply',      range: '5–6', color: '#3b82f6', bg: '#eff6ff',
      desc: 'Use information in new situations, solve problems using acquired knowledge.',
      verbs: 'Execute, implement, solve, use, demonstrate, operate',
      cvSignal: 'Skill used in a project, placement, or real-world task with tangible output.' },
    { level: 4, name: 'Analyse',    range: '7',   color: '#8b5cf6', bg: '#f5f3ff',
      desc: 'Draw connections, break down information, and differentiate between ideas.',
      verbs: 'Differentiate, organise, compare, deconstruct, attribute',
      cvSignal: 'Skill applied with evidence of problem-solving, architecture, or debugging complex issues.' },
    { level: 5, name: 'Evaluate',   range: '8–9', color: '#10b981', bg: '#f0fdf4',
      desc: 'Make judgements based on criteria, justify decisions, critique approaches.',
      verbs: 'Judge, justify, critique, assess, argue, defend',
      cvSignal: 'Skill used to make significant technical decisions, lead design reviews, or mentor others.' },
    { level: 6, name: 'Create',     range: '10',  color: '#1e3a8a', bg: '#eff6ff',
      desc: 'Produce new or original work, design, invent, or construct.',
      verbs: 'Design, construct, produce, plan, invent, compose',
      cvSignal: 'Built original systems, led innovation, or created solutions that others now use.' }
];

function bloomsLevelFromScore(score) {
    if (score >= 10) return 6;
    if (score >= 8)  return 5;
    if (score >= 7)  return 4;
    if (score >= 5)  return 3;
    if (score >= 3)  return 2;
    return 1;
}

function getBloomDesc(levelName, score) {
    const l = (levelName || '').toLowerCase();
    if (l.includes('create') || score >= 10) return 'You can synthesise new ideas, design original solutions, and produce novel work — you are pushing this skill forward.';
    if (l.includes('evaluat') || score >= 8) return 'You can critically assess and validate work, identify strengths and weaknesses, and make sound defensible decisions.';
    if (l.includes('analys') || score >= 7)  return 'You can break down complex problems, identify patterns, and diagnose issues within systems.';
    if (l.includes('apply') || score >= 5)   return 'You can apply this skill in real-world scenarios to solve practical problems — beyond theory into hands-on proficiency.';
    if (l.includes('understand') || score >= 3) return 'You understand the core concepts and can explain them, but are still building confidence in practical application.';
    return 'You have foundational awareness — you can recall key facts and definitions. With deliberate practice you can move up to applying and analysing.';
}

// ─── Load job titles dropdown ─────────────────────────────────
async function loadJobTitles() {
    try {
        const response = await fetch('/api/job-titles');
        const data     = await response.json();
        const select   = document.getElementById('jobSelect');
        data.jobTitles.forEach(job => {
            const o = document.createElement('option');
            o.value = job; o.textContent = job;
            select.appendChild(o);
        });
    } catch (e) { console.error('Error loading job titles:', e); }
}

// ─── Analyse job match ────────────────────────────────────────
document.getElementById('analyzeJobBtn').addEventListener('click', async () => {
    const selectedJob = document.getElementById('jobSelect').value;
    const customJob   = document.getElementById('customJob').value.trim();
    const jobTitle    = customJob || selectedJob;

    if (!jobTitle || jobTitle === 'undefined') {
        alert('Please select or enter a valid job title');
        return;
    }

    const btn = document.getElementById('analyzeJobBtn');
    btn.disabled = true;
    btn.classList.add('loading');
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Analysing…';

    try {
        const response = await fetch('/api/compare-with-job', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ jobTitle })
        });

        const result = await response.json();
        if (result.error) { alert('Error: ' + result.error); return; }

        lastJobResult = result;

        const readinessData = result.metrics.readiness || { score: 0, reasons: [], verdict: 'Unknown' };
        const relevanceData = result.metrics.relevance || { score: 0, reasons: [], verdict: 'Unknown' };

        document.getElementById('readinessScore').textContent = `${readinessData.score}%`;
        document.getElementById('relevanceScore').textContent = `${relevanceData.score}%`;

        // Colour the metric values
        document.getElementById('readinessScore').style.color = readinessData.score >= 70 ? '#10b981' : readinessData.score >= 50 ? '#f59e0b' : '#ef4444';
        document.getElementById('relevanceScore').style.color = relevanceData.score >= 70 ? '#10b981' : relevanceData.score >= 50 ? '#f59e0b' : '#ef4444';

        displayJobComparison(result);

        // Show the previously hidden sections
        document.getElementById('jobComparisonSection').style.display = 'grid';
        document.getElementById('metricsGrid').style.display = 'grid';

    } catch (e) {
        console.error('Error analyzing job:', e);
        alert('Error analyzing job match');
    } finally {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.innerHTML = '<i class="bi bi-search"></i> Analyse Match';
    }
});

// ─── Job comparison chart ─────────────────────────────────────
function displayJobComparison(result) {
    const canvas = document.getElementById('jobComparisonChart');
    const text   = document.getElementById('jobComparisonText');
    text.textContent = `Comparing your skills with: ${result.jobTitle}`;

    const matched = result.skillComparison.matchedSkills       || [];
    const missing = result.skillComparison.missingCriticalSkills|| [];

    const labels = [
        ...matched.map(s => s.skill + ' ✓'),
        ...missing.map(s => s + ' ✗')
    ];
    const scores = [
        ...matched.map(s => s.userScore),
        ...missing.map(() => 0)
    ];
    const colors = [
        ...matched.map(() => 'rgba(76,175,80,0.85)'),
        ...missing.map(() => 'rgba(244,67,54,0.85)')
    ];

    if (!labels.length) {
        text.textContent = 'No matching skills found. Try a different job title.';
        return;
    }

    if (jobComparisonChartInstance) jobComparisonChartInstance.destroy();

    jobComparisonChartInstance = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels,
            datasets: [{ label: 'Your Score', data: scores, backgroundColor: colors, borderColor: colors.map(c => c.replace('0.85','1')), borderWidth: 2, borderRadius: 5 }]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            scales: { y: { beginAtZero: true, max: 10 } },
            plugins: { legend: { display: false } }
        }
    });
}

// ─── Load & display results ───────────────────────────────────
async function loadAndDisplayResults() {
    let resultsData = null;

    const sessionData = sessionStorage.getItem('cvResults');
    if (sessionData) {
        try { resultsData = JSON.parse(sessionData); } catch(e) {}
    }

    if (!resultsData) {
        try {
            const response = await fetch('/api/latest-cv-analysis', { credentials: 'include' });
            const result   = await response.json();
            if (result.success && result.hasAnalysis) {
                resultsData = result.data;
            } else {
                window.location.href = '/dashboard';
                return;
            }
        } catch (e) {
            console.error(e);
            window.location.href = '/dashboard';
            return;
        }
    }

    globalResultsData = resultsData;
    displayResults(resultsData);
}

function displayResults(data) {
    const date = data.analyzedAt
        ? new Date(data.analyzedAt).toLocaleDateString('en-IE', { year:'numeric', month:'long', day:'numeric', hour:'2-digit', minute:'2-digit' })
        : new Date().toLocaleDateString('en-IE', { year:'numeric', month:'long', day:'numeric' });
    document.getElementById('userInfo').textContent = `Analysis completed on ${date}`;

    const skills = data.skills || [];
    globalSkillsData = skills;

    buildSkillsChart(skills);
    buildCategoryChart(data);
}

// ─── Skills bar chart ─────────────────────────────────────────
function buildSkillsChart(skills) {
    const barColors = skills.map(s =>
        s.score >= 8 ? 'rgba(16,185,129,0.85)' :
        s.score >= 7 ? 'rgba(107,163,213,0.85)' :
        s.score >= 5 ? 'rgba(245,158,11,0.85)'  :
                       'rgba(239,68,68,0.85)'
    );

    // Dynamic height: 36px per skill so every skill is visible
    const canvas = document.getElementById('skillsChart');
    canvas.style.height = Math.max(300, skills.length * 36) + 'px';

    if (skillsChartInstance) skillsChartInstance.destroy();

    skillsChartInstance = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: skills.map(s => s.name),
            datasets: [{
                label: "Bloom's Level (1–10)",
                data: skills.map(s => s.score),
                backgroundColor: barColors,
                borderColor: barColors.map(c => c.replace('0.85','1')),
                borderWidth: 2,
                borderRadius: 5
            }]
        },
        options: {
            indexAxis: 'y',          // horizontal bars — grows vertically with skill count
            responsive: true,
            maintainAspectRatio: false,
            onClick: (e, els) => { if (els.length) showSkillModal(els[0].index); },
            scales: {
                x: {
                    beginAtZero: true, max: 10,
                    ticks: { stepSize: 1 },
                    grid: { color: 'rgba(0,0,0,0.06)' }
                },
                y: {
                    ticks: { font: { size: 12, weight: 'bold' }, color: '#2C3E50' },
                    grid: { display: false }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        afterLabel: ctx => [
                            `Score: ${skills[ctx.dataIndex].score}/10`,
                            `Bloom's: ${skills[ctx.dataIndex].bloomLevel || 'N/A'}`,
                            `Category: ${skills[ctx.dataIndex].category}`,
                            'Click bar for full details'
                        ]
                    }
                }
            }
        }
    });
}

// ─── Category pie chart ───────────────────────────────────────
function buildCategoryChart(data) {
    const skillsByType = data.skillsByType || {};
    const typeLabels = [], typeCounts = [];

    ['technical','soft','business','domain','language','other'].forEach(k => {
        if (skillsByType[k] > 0) {
            typeLabels.push(CAT_KEY_MAP[k]);
            typeCounts.push(skillsByType[k]);
        }
    });

    const bgColors   = typeLabels.map(t => CAT_COLORS[t] || 'rgba(158,158,158,0.85)');
    const borderClrs = bgColors.map(c => c.replace('0.85','1'));

    if (categoryChartInstance) categoryChartInstance.destroy();

    categoryChartInstance = new Chart(
        document.getElementById('categoryChart').getContext('2d'), {
        type: 'pie',
        data: {
            labels: typeLabels,
            datasets: [{ data: typeCounts, backgroundColor: bgColors, borderColor: borderClrs, borderWidth: 2 }]
        },
        options: {
            responsive: true, maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: ctx => {
                            const pct = ((ctx.parsed / typeCounts.reduce((a,b)=>a+b,0))*100).toFixed(1);
                            return `${ctx.label}: ${ctx.parsed} skills (${pct}%)`;
                        }
                    }
                }
            }
        }
    });

    // Build legend
    const legend = document.getElementById('categoryLegend');
    legend.innerHTML = '';
    const total = typeCounts.reduce((a,b)=>a+b,0);
    typeLabels.forEach((type, i) => {
        const pct  = ((typeCounts[i]/total)*100).toFixed(1);
        const item = document.createElement('div');
        item.className = 'category-legend-item';
        item.innerHTML = `
            <div style="display:flex;align-items:center;">
                <span class="category-color" style="background:${bgColors[i]};"></span>
                <strong>${type}</strong>
            </div>
            <span>${typeCounts[i]} (${pct}%)</span>`;
        item.onclick = (e) => { e.stopPropagation(); showPieModal(type); };
        legend.appendChild(item);
    });
}

// ================================================================
//  SKILL DETAIL MODAL
// ================================================================
function showSkillModal(index) {
    const skill = globalSkillsData[index];
    if (!skill) return;

    const gap          = 7 - skill.score;
    const bloomLevel   = skill.bloomLevel || 'N/A';
    const bloomDesc    = getBloomDesc(bloomLevel, skill.score);
    const bloomNumeric = bloomsLevelFromScore(skill.score);
    const bloomData    = BLOOMS_LEVELS[bloomNumeric - 1];

    document.getElementById('skillModalTitle').textContent = skill.name;
    document.getElementById('skillModalBody').innerHTML = `

        <!-- Score bar -->
        <div class="modal-score-wrap">
            <div class="modal-score-label">
                <span>Your Score</span>
                <span style="font-size:1.1rem;color:#1e3a8a;">${skill.score}/10</span>
            </div>
            <div class="modal-score-track">
                <div class="modal-score-fill" style="width:${(skill.score/10)*100}%;">${skill.score}/10</div>
            </div>
            <div class="modal-score-gap" style="color:${gap<=0?'#10b981':gap<=2?'#f59e0b':'#ef4444'};">
                ${gap<=0
                    ? `✓ ${Math.abs(gap)} point${Math.abs(gap)!==1?'s':''} above the standard benchmark (7/10)`
                    : `${gap} point${gap!==1?'s':''} below the standard benchmark (7/10)`}
            </div>
        </div>

        <!-- Meta grid -->
        <div class="modal-meta-grid">
            <div class="modal-meta-item">
                <label>Category</label>
                <div class="val">${skill.category || 'N/A'}</div>
            </div>
            <div class="modal-meta-item">
                <label>Confidence</label>
                <div class="val">${skill.confidence || 'N/A'}</div>
            </div>
            <div class="modal-meta-item">
                <label>Method</label>
                <div class="val">${skill.method || skill.skillSource || 'N/A'}</div>
            </div>
            <div class="modal-meta-item">
                <label>Bloom's Level</label>
                <div class="val">
                    <span class="blooms-badge" onclick="showBloomsModal(${bloomNumeric}, '${skill.name}', ${skill.score})">
                        <i class="bi bi-layers"></i> ${bloomLevel} — click to learn more
                    </span>
                </div>
            </div>
        </div>

        <!-- What this score means -->
        <div class="mbox mbox-blue">
            <h4><i class="bi bi-layers"></i> What This Score Means (Bloom's Taxonomy)</h4>
            <p>${bloomDesc}</p>
        </div>

        <!-- Assessment basis -->
        ${skill.basis ? `
        <div class="mbox mbox-slate">
            <h4><i class="bi bi-clipboard-check"></i> Assessment Basis</h4>
            <p>${skill.basis}</p>
        </div>` : ''}

        <!-- Evidence -->
        ${skill.evidencePieces?.length ? `
        <div class="mbox mbox-green">
            <h4><i class="bi bi-file-text"></i> Evidence Found in Your CV</h4>
            <ul>${skill.evidencePieces.map(e=>`<li>${e}</li>`).join('')}</ul>
        </div>` : ''}

        <!-- How to improve -->
        <div class="mbox mbox-amber">
            <h4><i class="bi bi-lightbulb"></i> How to Strengthen This Skill</h4>
            <ul>
                ${skill.score < 7 ? `<li>Add concrete examples of using ${skill.name} in projects to your CV</li>` : ''}
                ${skill.score < 5 ? `<li>Consider a short course or certification to build hands-on experience</li>` : ''}
                <li>Move from "${bloomData?.name || 'current level'}" toward ${bloomNumeric < 6 ? `"${BLOOMS_LEVELS[bloomNumeric]?.name || 'the next level'}"` : 'maintaining expert status'} by applying the skill in new, complex contexts</li>
                ${skill.score >= 7 ? `<li>You are above benchmark — highlight this skill prominently in interviews and applications</li>` : ''}
            </ul>
        </div>
    `;

    openModal('skillModal');
}

// ================================================================
//  BLOOMS TAXONOMY MODAL (second-layer from skill modal)
// ================================================================
function showBloomsModal(currentLevel, skillName, score) {
    const bloomDesc = getBloomDesc('', score);

    document.getElementById('bloomsModalBody').innerHTML = `
        <div class="mbox mbox-blue" style="margin-bottom:18px;">
            <h4><i class="bi bi-info-circle"></i> How Bloom's Taxonomy Was Used</h4>
            <p>CVision uses Bloom's Taxonomy to assess <em>depth of knowledge</em> — not just whether you know a skill, but how deeply you can use it. Your CV text is analysed by AI to find evidence of each cognitive level. <strong>${skillName}</strong> scored <strong>${score}/10</strong> — placing it at the <strong>${BLOOMS_LEVELS[currentLevel-1]?.name}</strong> level.</p>
        </div>

        <div class="blooms-pyramid">
            ${BLOOMS_LEVELS.map((lvl, i) => {
                const isActive = (i + 1) === currentLevel;
                return `
                <div class="blooms-level-row ${isActive ? 'highlight' : ''}"
                     style="background:${isActive ? lvl.bg : '#f8f9fa'}; border-left-color:${isActive ? lvl.color : '#e5e7eb'};">
                    <div class="blooms-num" style="color:${lvl.color};">${lvl.level}</div>
                    <div style="flex:1;">
                        <div class="blooms-name" style="color:${isActive ? lvl.color : '#374151'};">
                            ${lvl.name} ${isActive ? '<span style="font-size:0.75rem;margin-left:6px;background:'+lvl.color+';color:white;padding:2px 8px;border-radius:10px;">YOUR LEVEL</span>' : ''}
                        </div>
                        <div class="blooms-desc">${lvl.desc}</div>
                        <div style="font-size:0.78rem;color:#9ca3af;margin-top:3px;">
                            <em>Key verbs:</em> ${lvl.verbs}
                        </div>
                        ${isActive ? `<div style="font-size:0.8rem;margin-top:5px;color:${lvl.color};font-weight:600;">CV signal: ${lvl.cvSignal}</div>` : ''}
                    </div>
                    <div class="blooms-score-badge" style="background:${lvl.color};">${lvl.range}</div>
                </div>`;
            }).join('')}
        </div>

        <div class="mbox mbox-green" style="margin-top:14px;">
            <h4><i class="bi bi-arrow-up-circle"></i> To Reach the Next Level</h4>
            ${currentLevel < 6
                ? `<p>To move from <strong>${BLOOMS_LEVELS[currentLevel-1]?.name}</strong> to <strong>${BLOOMS_LEVELS[currentLevel]?.name}</strong>, focus on: <em>${BLOOMS_LEVELS[currentLevel]?.verbs}</em></p>
                   <p style="margin-top:6px;">Add CV evidence that shows you can ${BLOOMS_LEVELS[currentLevel]?.desc.toLowerCase()}</p>`
                : `<p>You are already at the highest Bloom's level — <strong>Create</strong>. Maintain this by continuing to build, design, and innovate.</p>`}
        </div>
    `;

    // Keep backdrop, open blooms on top
    document.getElementById('bloomsModal').classList.add('show');
}

function closeBlooms() {
    document.getElementById('bloomsModal').classList.remove('show');
}

// ================================================================
//  PIE CHART MODAL
// ================================================================
function showPieModal(focusCategory) {
    if (!globalResultsData) return;
    const skills     = globalResultsData.skills || [];
    const skillsType = globalResultsData.skillsByType || {};
    const total      = Object.values(skillsType).reduce((a,b)=>a+b,0);

    const order = ['technical','soft','business','domain','language','other'];

    document.getElementById('pieModalBody').innerHTML = `
        <p style="color:#555;font-size:0.9rem;margin-bottom:16px;">
            Your CV contains <strong>${total} skills</strong> across ${Object.keys(skillsType).filter(k=>skillsType[k]>0).length} categories. 
            Click any category to see the individual skills.
        </p>
        <ul class="pie-slice-list" id="pieSliceList"></ul>
    `;

    const list = document.getElementById('pieSliceList');

    order.forEach(key => {
        const count = skillsType[key] || 0;
        if (!count) return;

        const label    = CAT_KEY_MAP[key];
        const color    = CAT_COLORS[label] || 'rgba(158,158,158,0.85)';
        const pct      = ((count/total)*100).toFixed(1);
        const catSkills= skills.filter(s => s.category === key || s.skillType === key);
        const isOpen   = focusCategory === label;

        const li = document.createElement('li');
        li.className = 'pie-slice-item';
        li.style.borderLeftColor = color.replace('0.85','1');
        li.innerHTML = `
            <div class="pie-slice-header" onclick="togglePieSlice(this)">
                <span class="pie-slice-dot" style="background:${color.replace('0.85','1')};"></span>
                <span class="pie-slice-name">${label}</span>
                <span class="pie-slice-meta">${count} skill${count!==1?'s':''}</span>
                <span class="pie-slice-pct" style="color:${color.replace('0.85','1')};">${pct}%</span>
                <i class="bi bi-chevron-down" style="margin-left:6px;font-size:0.8rem;color:#aaa;transition:transform 0.2s;"></i>
            </div>
            <div class="skill-mini-list ${isOpen ? 'open' : ''}">
                ${catSkills.length
                    ? catSkills.sort((a,b)=>b.score-a.score).map(s => {
                        const sc = s.score;
                        const bg = sc>=8?'#10b981':sc>=7?'#6BA3D5':sc>=5?'#f59e0b':'#ef4444';
                        return `<div class="skill-mini-row">
                            <span>${s.name}</span>
                            <span class="skill-mini-score" style="background:${bg};">${sc}/10</span>
                        </div>`;
                    }).join('')
                    : '<div style="font-size:0.85rem;color:#aaa;padding:6px 0;">No skills in this category</div>'}
            </div>`;
        list.appendChild(li);
    });

    openModal('pieModal');
}

function togglePieSlice(headerEl) {
    const list     = headerEl.nextElementSibling;
    const chevron  = headerEl.querySelector('.bi-chevron-down, .bi-chevron-up');
    const isOpen   = list.classList.contains('open');
    list.classList.toggle('open', !isOpen);
    if (chevron) {
        chevron.classList.toggle('bi-chevron-down', isOpen);
        chevron.classList.toggle('bi-chevron-up', !isOpen);
    }
}

// ================================================================
//  METRIC MODALS (Readiness + Relevance)
// ================================================================
function showMetricModal(type) {
    if (!lastJobResult) return;

    const readData = lastJobResult.metrics.readiness || {};
    const relData  = lastJobResult.metrics.relevance  || {};
    const ud       = lastJobResult.userData || {};

    let title = '', body = '';

    if (type === 'readiness') {
        const score   = readData.score || 0;
        const verdict = readData.verdict || '';
        const reasons = readData.reasons || [];
        const color   = score >= 70 ? 'linear-gradient(135deg,#10b981,#34d399)' : score >= 50 ? 'linear-gradient(135deg,#f59e0b,#fbbf24)' : 'linear-gradient(135deg,#ef4444,#f87171)';

        title = 'Career Readiness Breakdown';
        body  = `
            <div class="metric-hero" style="background:${color};">
                <div class="big-pct">${score}%</div>
                <div class="verdict">${verdict}</div>
            </div>

            <div class="metric-row"><span class="mi"><i class="bi bi-mortarboard-fill" style="color:#8b5cf6;"></i></span><div><div class="ml">Education Years</div><div class="mv">${ud.educationYears ?? '--'} year${ud.educationYears !== 1 ? 's' : ''}</div></div></div>
            <div class="metric-row"><span class="mi"><i class="bi bi-briefcase-fill" style="color:#3b82f6;"></i></span><div><div class="ml">Industry Years</div><div class="mv">${ud.industryYears ?? '--'} year${ud.industryYears !== 1 ? 's' : ''}</div></div></div>
            <div class="metric-row"><span class="mi"><i class="bi bi-star-fill" style="color:#f59e0b;"></i></span><div><div class="ml">Strong Skills (≥7/10)</div><div class="mv">${ud.strongSkills ?? '--'} skills</div></div></div>
            <div class="metric-row"><span class="mi"><i class="bi bi-collection-fill" style="color:#6BA3D5;"></i></span><div><div class="ml">Total Skills Found</div><div class="mv">${ud.totalSkills ?? '--'} skills</div></div></div>

            ${reasons.length ? `
            <div class="mbox mbox-blue" style="margin-top:14px;">
                <h4><i class="bi bi-list-check"></i> Detailed Reasons</h4>
                <ul>${reasons.map(r=>`<li>${r}</li>`).join('')}</ul>
            </div>` : ''}

            <div class="mbox mbox-${score>=70?'green':score>=50?'amber':'slate'}" style="margin-top:12px;">
                <h4><i class="bi bi-lightbulb"></i> What to Do Next</h4>
                ${score >= 70
                    ? `<p>You are well-positioned for this role. Focus on tailoring your CV language to match the job description and preparing strong examples for interview.</p>`
                    : score >= 50
                        ? `<p>You are approaching readiness. Consider taking on project work or short courses to bridge the remaining gap before applying.</p>`
                        : `<p>There are significant gaps to address. Build the missing skills over the next 3–6 months through projects, certifications, or coursework.</p>`}
            </div>`;

    } else {
        const score   = relData.score || 0;
        const verdict = relData.verdict || '';
        const reasons = relData.reasons || [];
        const color   = score >= 70 ? 'linear-gradient(135deg,#3b82f6,#60a5fa)' : score >= 50 ? 'linear-gradient(135deg,#8b5cf6,#a78bfa)' : 'linear-gradient(135deg,#6b7280,#9ca3af)';

        title = 'Experience Relevance Breakdown';
        body  = `
            <div class="metric-hero" style="background:${color};">
                <div class="big-pct">${score}%</div>
                <div class="verdict">${verdict}</div>
            </div>

            <div class="metric-row"><span class="mi"><i class="bi bi-calendar-check-fill" style="color:#3b82f6;"></i></span><div><div class="ml">Industry Experience</div><div class="mv">${ud.industryYears ?? '--'} year${ud.industryYears !== 1 ? 's' : ''}</div></div></div>
            <div class="metric-row"><span class="mi"><i class="bi bi-mortarboard-fill" style="color:#8b5cf6;"></i></span><div><div class="ml">Education Years</div><div class="mv">${ud.educationYears ?? '--'} year${ud.educationYears !== 1 ? 's' : ''}</div></div></div>
            <div class="metric-row"><span class="mi"><i class="bi bi-check-circle-fill" style="color:#10b981;"></i></span><div><div class="ml">Skills Matched to Role</div><div class="mv">${(lastJobResult.skillComparison?.matchedSkills?.length) ?? '--'} matched</div></div></div>
            <div class="metric-row"><span class="mi"><i class="bi bi-exclamation-triangle-fill" style="color:#ef4444;"></i></span><div><div class="ml">Critical Skills Missing</div><div class="mv">${(lastJobResult.skillComparison?.missingCriticalSkills?.length) ?? '--'} missing</div></div></div>

            ${reasons.length ? `
            <div class="mbox mbox-blue" style="margin-top:14px;">
                <h4><i class="bi bi-list-check"></i> Detailed Reasons</h4>
                <ul>${reasons.map(r=>`<li>${r}</li>`).join('')}</ul>
            </div>` : ''}

            <div class="mbox mbox-green" style="margin-top:12px;">
                <h4><i class="bi bi-lightbulb"></i> How to Improve Relevance</h4>
                <ul>
                    <li>Use keywords from the job description in your CV summary and experience sections</li>
                    <li>Quantify your achievements with numbers (e.g. "reduced load time by 40%")</li>
                    <li>Ensure the most relevant skills appear prominently — not buried</li>
                    ${ud.industryYears < 2 ? '<li>Internships, placements, and part-time roles count as industry experience — list them clearly</li>' : ''}
                </ul>
            </div>`;
    }

    document.getElementById('metricModalTitle').textContent = title;
    document.getElementById('metricModalBody').innerHTML     = body;
    openModal('metricModal');
}

// ================================================================
//  MODAL HELPERS
// ================================================================
function openModal(id) {
    document.getElementById('modalBackdrop').classList.add('show');
    document.getElementById(id).classList.add('show');
}

function closeAllModals() {
    document.getElementById('modalBackdrop').classList.remove('show');
    ['skillModal','pieModal','metricModal','bloomsModal'].forEach(id => {
        document.getElementById(id).classList.remove('show');
    });
}

// ─── Navbar ───────────────────────────────────────────────────
async function updateNavbar() {
    try {
        const res  = await fetch('/session-info', { credentials: 'include' });
        const data = await res.json();
        if (data.loggedIn) document.getElementById('profileNav').style.display = 'flex';
        else window.location.href = '/login';
    } catch(e) { console.error('Navbar check failed', e); }
}

// ─── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    updateNavbar();
    loadJobTitles();
    loadAndDisplayResults();
});