const OpenAI = require('openai');

/* ================================
   SKILL CATEGORIES & WEIGHTS
   ================================ */

const SKILL_CATEGORIES = {
    "Programming Languages": {
        keywords: [
            "javascript", "js", "python", "java", "c++", "cpp", "c#", "csharp", 
            "php", "ruby", "go", "golang", "rust", "typescript", "ts", "swift",
            "kotlin", "scala", "perl", "r", "matlab", "vba", "objective-c"
        ],
        weight: 1.0,
        type: "technical"
    },
    "Web Development": {
        keywords: [
            "html", "css", "sass", "scss", "less", "react", "reactjs", "vue", 
            "vuejs", "angular", "node", "nodejs", "express", "expressjs", 
            "bootstrap", "tailwind", "django", "flask", "spring", "laravel",
            "wordpress", "jquery", "nextjs", "gatsby", "svelte", "frontend",
            "backend", "full stack", "fullstack", "web development", "ajax"
        ],
        weight: 0.9,
        type: "technical"
    },
    "Databases": {
        keywords: [
            "sql", "postgresql", "postgres", "mysql", "mongodb", "mongo", 
            "redis", "sqlite", "oracle", "database", "db", "cassandra",
            "mariadb", "dynamodb", "firebase", "firestore", "supabase"
        ],
        weight: 0.85,
        type: "technical"
    },
    "AI & Data Science": {
        keywords: [
            "machine learning", "ml", "data analysis", "data science", 
            "nlp", "ai", "artificial intelligence", "tensorflow", "pytorch", 
            "pandas", "numpy", "scikit-learn", "sklearn", "deep learning",
            "neural network", "data mining", "big data", "analytics",
            "statistics", "data visualization", "tableau", "power bi"
        ],
        weight: 0.95,
        type: "technical"
    },
    "Cloud & DevOps": {
        keywords: [
            "docker", "kubernetes", "k8s", "aws", "amazon web services", 
            "azure", "microsoft azure", "gcp", "google cloud", "jenkins", 
            "ci/cd", "terraform", "ansible", "chef", "puppet", "devops",
            "cloud", "heroku", "netlify", "vercel", "gitlab", "circleci"
        ],
        weight: 0.8,
        type: "technical"
    },
    "Development Tools": {
        keywords: [
            "git", "github", "gitlab", "bitbucket", "jira", "confluence",
            "slack", "trello", "asana", "vscode", "visual studio", "intellij",
            "eclipse", "pycharm", "sublime", "atom", "vim", "emacs", "postman"
        ],
        weight: 0.6,
        type: "technical"
    },
    "Design & Creative": {
        keywords: [
            "figma", "photoshop", "illustrator", "adobe", "sketch", "xd",
            "ui", "ux", "ui/ux", "design", "graphic design", "web design",
            "canva", "indesign", "after effects", "premiere", "blender"
        ],
        weight: 0.7,
        type: "technical"
    },
    "Mobile Development": {
        keywords: [
            "android", "ios", "mobile", "react native", "flutter", "swift",
            "kotlin", "xamarin", "cordova", "ionic", "mobile development",
            "app development"
        ],
        weight: 0.9,
        type: "technical"
    },
    "Testing & QA": {
        keywords: [
            "testing", "test", "qa", "quality assurance", "selenium", 
            "jest", "mocha", "chai", "cypress", "junit", "pytest",
            "unit test", "integration test", "automation"
        ],
        weight: 0.7,
        type: "technical"
    },
    "Soft Skills": {
        keywords: [
            "communication", "teamwork", "leadership", "problem solving", 
            "critical thinking", "time management", "collaboration",
            "presentation", "public speaking", "mentoring", "coaching",
            "interpersonal", "adaptability", "creativity", "work ethic"
        ],
        weight: 0.7,
        type: "soft"
    },
    "Business & Management": {
        keywords: [
            "project management", "agile", "scrum", "kanban", "pmp",
            "business analysis", "strategy", "planning", "budgeting",
            "stakeholder", "product management", "marketing"
        ],
        weight: 0.75,
        type: "business"
    }
};

// IMPROVED: Detect category with better matching and avoid "Programming Languages" for non-programming skills
function detectCategory(skill) {
    const s = skill.toLowerCase().trim();
    
    // First, check for exact matches or strong indicators
    for (const category in SKILL_CATEGORIES) {
        const keywords = SKILL_CATEGORIES[category].keywords;
        
        for (const keyword of keywords) {
            // Exact match
            if (s === keyword) {
                return {
                    category: category,
                    weight: SKILL_CATEGORIES[category].weight,
                    type: SKILL_CATEGORIES[category].type
                };
            }
            
            // Contains keyword (but avoid partial matches for programming languages)
            if (category === "Programming Languages") {
                // Only match if it's clearly a programming language
                if (s.includes(keyword) && (
                    s.includes('programming') || 
                    s.includes('language') ||
                    s.includes('coding') ||
                    s === keyword // Exact match already handled above, but keeping for clarity
                )) {
                    return {
                        category: category,
                        weight: SKILL_CATEGORIES[category].weight,
                        type: SKILL_CATEGORIES[category].type
                    };
                }
            } else {
                // For non-programming categories, allow partial matches
                if (s.includes(keyword) || keyword.includes(s)) {
                    return {
                        category: category,
                        weight: SKILL_CATEGORIES[category].weight,
                        type: SKILL_CATEGORIES[category].type
                    };
                }
            }
        }
    }
    
    // Intelligent fallback patterns
    if (s.match(/^[a-z]+\+\+$|^[a-z]#$/)) {
        return { category: "Programming Languages", weight: 1.0, type: "technical" };
    }
    
    if (s.includes('database') || s.includes('db') || s.endsWith('sql')) {
        return { category: "Databases", weight: 0.85, type: "technical" };
    }
    
    if (s.includes('framework') || s.endsWith('js') || s.endsWith('.js')) {
        return { category: "Web Development", weight: 0.9, type: "technical" };
    }
    
    if (s.includes('cloud') || s.includes('aws') || s.includes('azure')) {
        return { category: "Cloud & DevOps", weight: 0.8, type: "technical" };
    }
    
    // Default to Technical Skills instead of Other
    return { category: "Technical Skills", weight: 0.5, type: "technical" };
}

// proficiency calculation
function calculateProficiency(skill, cvText, industryYears, educationYears) {
    const skillLower = skill.toLowerCase();
    const textLower = cvText.toLowerCase();
    const skillIndex = textLower.indexOf(skillLower);
    
    // Count skill mentions for frequency analysis
    const skillMentions = (textLower.match(new RegExp(skillLower, 'g')) || []).length;
    
    // If skill not found use timeline estimation with low confidence
    if (skillIndex === -1) {
        const timelineResult = estimateByTimeline(industryYears, educationYears, skillMentions);
        return {
            ...timelineResult,
            confidence: 'Very Low',
            evidenceCount: 0,
            evidencePieces: [],
            method: 'Timeline estimation only',
            supported: false
        };
    }
    
    // Extract context around skill mention
    const start = Math.max(0, skillIndex - 200);
    const end = Math.min(textLower.length, skillIndex + 200);
    const context = textLower.substring(start, end);
    
    // Count evidence pieces
    let evidenceCount = 0;
    let evidencePieces = [];
    
    // Bloom's Taxonomy with outcomes
    const expertKeywords = ['designed', 'architected', 'invented', 'pioneered', 'created framework', 'from scratch', 'published', 'taught', 'leading expert'];
    const expertWithOutcome = /(designed|architected|created).*?(system|architecture|framework|solution)/i.test(context);
    
    if (expertKeywords.some(kw => context.includes(kw))) {
        evidenceCount++;
        evidencePieces.push('Innovation/Creation verbs found');
    }
    
    if (expertWithOutcome) {
        evidenceCount++;
        evidencePieces.push('Design/Architecture with measurable outcome');
    }
    
    const advancedKeywords = ['optimized', 'improved', 'debugged complex', 'led', 'mentored', 'reviewed', 'evaluated', 'designed system'];
    const advancedWithMetric = /(optimized|improved|reduced|increased).*?(\d+%|\d+x)/i.test(context);
    
    if (advancedKeywords.some(kw => context.includes(kw))) {
        evidenceCount++;
        evidencePieces.push('Problem-solving verbs found');
    }
    
    if (advancedWithMetric) {
        evidenceCount++;
        evidencePieces.push('Quantified improvement detected');
    }
    
    const intermediateKeywords = ['built', 'developed', 'created', 'implemented', 'worked on', 'contributed', 'deployed', 'managed'];
    const hasProjects = /(\d+)\s*(project|app|application|system)/i.test(context);
    const projectMatch = context.match(/(\d+)\s*(project|app|application|system)/i);
    
    if (intermediateKeywords.some(kw => context.includes(kw))) {
        evidenceCount++;
        evidencePieces.push('Application/Implementation verbs found');
    }
    
    if (hasProjects) {
        evidenceCount++;
        evidencePieces.push(`${projectMatch[1]} project(s) mentioned`);
    }
    
    // Check for explicit years
    const yearMatch = context.match(/(\d+)\s*year/i);
    if (yearMatch) {
        evidenceCount++;
        evidencePieces.push(`${yearMatch[1]} years explicitly mentioned`);
    }
    
    const beginnerKeywords = ['familiar', 'basic', 'learned', 'studied', 'knowledge of', 'exposure to', 'introduced to'];
    if (beginnerKeywords.some(kw => context.includes(kw))) {
        evidenceCount++;
        evidencePieces.push('Beginner-level language detected');
    }
    
    // Count frequency
    if (skillMentions > 1) {
        evidenceCount++;
        evidencePieces.push(`Skill mentioned ${skillMentions} times`);
    }
    
    //Require multiple pieces of evidence for high scores
    let score, bloomLevel, basis;
    
    // Expert level (Create) - REQUIRES 3+ evidence pieces
    if (evidenceCount >= 3 && (expertWithOutcome || expertKeywords.some(kw => context.includes(kw)))) {
        score = 9;
        bloomLevel = 'Create';
        basis = 'Expert - Innovation/Creation with strong evidence';
    }
    // Advanced level (Evaluate/Analyze)
    else if (evidenceCount >= 2 && (advancedWithMetric || advancedKeywords.some(kw => context.includes(kw)))) {
        score = 8;
        bloomLevel = 'Evaluate';
        basis = 'Advanced - Problem solving with measurable outcomes';
    }
    // Intermediate level (Apply)
    else if (evidenceCount >= 2 && (hasProjects || intermediateKeywords.some(kw => context.includes(kw)))) {
        score = hasProjects ? 7 : 6;
        bloomLevel = 'Apply';
        basis = 'Intermediate - Applied in projects';
    }
    // With explicit years
    else if (yearMatch) {
        const years = parseInt(yearMatch[1]);
        score = Math.min(3 + years, 8);
        bloomLevel = years >= 3 ? 'Apply' : 'Understand';
        basis = `${years} years explicit experience`;
    }
    // Beginner level
    else if (beginnerKeywords.some(kw => context.includes(kw))) {
        score = 3;
        bloomLevel = 'Understand';
        basis = 'Beginner - Basic knowledge';
    }
    // IMPROVEMENT 8: Severely cap unsupported skills
    else if (evidenceCount <= 1) {
        score = 2.5;
        bloomLevel = 'Remember';
        basis = 'Skill listed but not demonstrated';
    }
    else {
        const timelineResult = estimateByTimeline(industryYears, educationYears, skillMentions);
        return {
            ...timelineResult,
            evidenceCount,
            evidencePieces,
            method: 'Timeline estimation',
            bloomLevel: 'Remember'
        };
    }
    
    // IMPROVEMENT 2: Confidence based on evidence count
    let confidence;
    if (evidenceCount >= 3) {
        confidence = 'High';
    } else if (evidenceCount >= 2) {
        confidence = 'Medium';
    } else {
        confidence = 'Low';
    }
    
    // IMPROVEMENT 6: Detect academic vs professional
    const academicContext = /(university|college|course|degree|thesis|assignment|project\s+work)/i.test(context);
    const professionalContext = /(company|employment|job|work|professional|client|production)/i.test(context);
    
    let skillSource = 'Unknown';
    if (professionalContext) {
        skillSource = 'Professional';
    } else if (academicContext) {
        skillSource = 'Academic';
    }
    
    return {
        score,
        confidence,
        basis,
        bloomLevel,
        evidenceCount,
        evidencePieces,
        skillSource,
        method: 'Context analysis',
        supported: evidenceCount >= 2
    };
}

// timeline estimation
function estimateByTimeline(industryYears, educationYears, mentionCount = 1) {
    const frequencyBonus = mentionCount > 2 ? 0.5 : 0;
    
    if (industryYears >= 1) {
        let score;
        if (industryYears === 1) score = 3;
        else if (industryYears === 2) score = 3.5;
        else if (industryYears === 3) score = 4;
        else score = 4.5;
        
        score += frequencyBonus;
        
        return { 
            score: Math.min(score, 5),
            confidence: 'Very Low', 
            basis: `${industryYears} industry year(s) - no concrete evidence`,
            bloomLevel: 'Remember'
        };
    }
    
    if (!educationYears || educationYears < 1) {
        return { score: 2, confidence: 'Very Low', basis: 'No timeline info', bloomLevel: 'Remember' };
    } else if (educationYears === 1) {
        return { score: 2.5, confidence: 'Very Low', basis: '1 education year - no evidence', bloomLevel: 'Remember' };
    } else if (educationYears === 2) {
        return { score: 3, confidence: 'Very Low', basis: '2 education years - no evidence', bloomLevel: 'Remember' };
    } else if (educationYears === 3) {
        return { score: 3.5, confidence: 'Very Low', basis: '3 education years - no evidence', bloomLevel: 'Remember' };
    }
    return { score: 4, confidence: 'Very Low', basis: `${educationYears}+ education years - no evidence`, bloomLevel: 'Understand' };
}

function extractEducationYears(education) {
    if (!education || education.length === 0) return 0;
    const currentYear = new Date().getFullYear();
    
    for (const edu of education) {
        const yearPattern = /(\d{4})\s*[-–—]\s*(\d{4}|present|current)/i;
        const match = edu.match(yearPattern);
        if (match) {
            const startYear = parseInt(match[1]);
            const endYear = match[2].toLowerCase() === 'present' || match[2].toLowerCase() === 'current' 
                ? currentYear : parseInt(match[2]);
            return endYear - startYear;
        }
        
        const singleYearPattern = /(?:started|since|from)\s*(\d{4})/i;
        const singleMatch = edu.match(singleYearPattern);
        if (singleMatch) return currentYear - parseInt(singleMatch[1]);
    }
    return 0;
}

function extractIndustryYears(experience) {
    if (!experience || experience.length === 0) return 0;
    const currentYear = new Date().getFullYear();
    let totalYears = 0;
    
    for (const exp of experience) {
        const yearPattern = /(\d{4})\s*[-–—]\s*(\d{4}|present|current)/i;
        const match = exp.match(yearPattern);
        if (match) {
            const startYear = parseInt(match[1]);
            const endYear = match[2].toLowerCase() === 'present' || match[2].toLowerCase() === 'current' 
                ? currentYear : parseInt(match[2]);
            totalYears += (endYear - startYear);
        }
    }
    return totalYears;
}

async function extractPDFText(filePath) {
    const fs = require('fs');
    const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
    const data = new Uint8Array(fs.readFileSync(filePath));
    const pdf = await pdfjsLib.getDocument({ data }).promise;
    let text = '';
    
    for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        const pageText = content.items.map(item => item.str).join(' ');
        text += pageText + '\n';
    }
    return text;
}

module.exports = {
    calculateProficiency,
    detectCategory,
    extractEducationYears,
    extractIndustryYears,
    extractPDFText,
    SKILL_CATEGORIES
};