const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');
const multer = require('multer');
const fs = require('fs');
const mammoth = require('mammoth');
const OpenAI = require('openai');
require('dotenv').config();

const app = express();
const PORT = 3000;

/* ================================
   DATABASE CONNECTION
   ================================ */

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});


/* ================================
   FILE UPLOAD & OPENAI SETUP
   ================================ */

const upload = multer({ dest: 'uploads/' });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ================================
   MIDDLEWARE
   ================================ */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'cvision-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname)));

/* ================================
   CV ANALYSIS FUNCTIONS
   ================================ */

async function extractPDFText(filePath) {
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

function calculateProficiency(skill, cvText, industryYears, educationYears) {
    const skillLower = skill.toLowerCase();
    const textLower = cvText.toLowerCase();
    const skillIndex = textLower.indexOf(skillLower);
    
    if (skillIndex === -1) return estimateByTimeline(industryYears, educationYears);
    
    const start = Math.max(0, skillIndex - 200);
    const end = Math.min(textLower.length, skillIndex + 200);
    const context = textLower.substring(start, end);
    
    const expertKeywords = ['designed', 'architected', 'invented', 'pioneered', 'created framework', 'from scratch', 'published', 'taught', 'leading expert'];
    if (expertKeywords.some(kw => context.includes(kw))) {
        return { score: 9, confidence: 'High', basis: 'Expert - Innovation/Creation' };
    }
    
    const advancedKeywords = ['optimized', 'improved', 'debugged complex', 'led', 'mentored', 'reviewed', 'evaluated', 'designed system'];
    if (advancedKeywords.some(kw => context.includes(kw))) {
        return { score: 8, confidence: 'High', basis: 'Advanced - Problem solving' };
    }
    
    const intermediateKeywords = ['built', 'developed', 'created', 'implemented', 'worked on', 'contributed', 'deployed', 'managed'];
    const hasProjects = /\d+\s*(project|app|application|system)/i.test(context);
    
    if (intermediateKeywords.some(kw => context.includes(kw)) || hasProjects) {
        return { score: hasProjects ? 7 : 6, confidence: 'Medium', basis: 'Intermediate - Applied in projects' };
    }
    
    const yearMatch = context.match(/(\d+)\s*year/i);
    if (yearMatch) {
        const years = parseInt(yearMatch[1]);
        return { score: Math.min(3 + years, 8), confidence: 'Medium', basis: `${years} years explicit experience` };
    }
    
    const beginnerKeywords = ['familiar', 'basic', 'learned', 'studied', 'knowledge of', 'exposure to', 'introduced to'];
    if (beginnerKeywords.some(kw => context.includes(kw))) {
        return { score: 3, confidence: 'Medium', basis: 'Beginner - Basic knowledge' };
    }
    
    return estimateByTimeline(industryYears, educationYears);
}

function estimateByTimeline(industryYears, educationYears) {
    if (industryYears >= 1) {
        if (industryYears === 1) return { score: 3, confidence: 'Very Low', basis: '1 industry year (no evidence)' };
        if (industryYears === 2) return { score: 3.5, confidence: 'Very Low', basis: '2 industry years (no evidence)' };
        if (industryYears === 3) return { score: 4, confidence: 'Very Low', basis: '3 industry years (no evidence)' };
        return { score: 4.5, confidence: 'Very Low', basis: `${industryYears}+ industry years (no evidence)` };
    }
    
    if (!educationYears || educationYears < 1) {
        return { score: 2, confidence: 'Very Low', basis: 'No timeline info (no evidence)' };
    } else if (educationYears === 1) {
        return { score: 2.5, confidence: 'Very Low', basis: '1 education year (no evidence)' };
    } else if (educationYears === 2) {
        return { score: 3, confidence: 'Very Low', basis: '2 education years (no evidence)' };
    } else if (educationYears === 3) {
        return { score: 3.5, confidence: 'Very Low', basis: '3 education years (no evidence)' };
    }
    return { score: 4, confidence: 'Very Low', basis: `${educationYears}+ education years (no evidence)` };
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

/* ================================
   ROUTES
   ================================ */

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
/* ================================
   LOGIN ROUTES
   ================================ */

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).send('Invalid email or password');
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.status(401).send('Invalid email or password');
        }

        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.fullName = user.full_name;

        res.redirect('/dashboard');

    } catch (err) {
        console.error(err);
        res.status(500).send('Login failed');
    }
});


app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.post('/signup', async (req, res) => {
    const { fullName, email, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users (full_name, email, password_hash, role)
             VALUES ($1, $2, $3, $4)
             RETURNING id`,
            [fullName, email, hashedPassword, role]
        );

        req.session.userId = result.rows[0].id;
        req.session.role = role;
        req.session.fullName = fullName;

        res.redirect('/dashboard');

    } catch (err) {
        console.error(err);
        res.status(500).send('Error creating account');
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/signup');
    }

    if (req.session.role === 'recruiter') {
        res.sendFile(path.join(__dirname, 'dashboard-recruiter.html'));
    } else {
        res.sendFile(path.join(__dirname, 'dashboard-user.html'));
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Logout failed');
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

app.post('/analyze', upload.single('cvFile'), async (req, res) => {
    try {
        if (!req.file) return res.json({ error: 'No file uploaded' });

        if (!openai || !process.env.OPENAI_API_KEY) {
            return res.json({ error: 'OpenAI API key not configured' });
        }

        let text = req.file.originalname.toLowerCase().endsWith('.pdf') 
            ? await extractPDFText(req.file.path)
            : (await mammoth.extractRawText({ path: req.file.path })).value;
        
        fs.unlinkSync(req.file.path);
        
        if (!text || text.length < 10) {
            return res.json({ error: 'Could not extract text from file' });
        }

        const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{
                role: 'user',
                content: `Extract CV data as JSON:
{
  "skills": ["skill1", "skill2"],
  "education": ["University, Degree, 2022-2025"],
  "experience": ["Job at Company, 2023-Present"]
}
Include years in YYYY-YYYY or YYYY-Present format.

CV: ${text.substring(0, 3000)}`
            }],
            response_format: { type: 'json_object' }
        });

        const data = JSON.parse(response.choices[0].message.content);
        
        const educationYears = extractEducationYears(data.education || []);
        const industryYears = extractIndustryYears(data.experience || []);
        
        const skillsWithProficiency = (data.skills || []).map(skill => {
            const proficiency = calculateProficiency(skill, text, industryYears, educationYears);
            return {
                name: skill,
                score: proficiency.score,
                confidence: proficiency.confidence,
                basis: proficiency.basis
            };
        });
        
        res.json({
            skills: skillsWithProficiency,
            education: data.education || [],
            experience: data.experience || [],
            educationYears: educationYears,
            industryYears: industryYears
        });
        
    } catch (error) {
        console.error('Error analyzing CV:', error);
        res.json({ error: error.message });
    }
});

app.get('/results', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/signup');
    }
    res.sendFile(path.join(__dirname, 'results.html'));
});

app.listen(PORT, () => {
    console.log(`CVision running at http://localhost:${PORT}`);
    if (!process.env.OPENAI_API_KEY) {
        console.log('⚠️  Warning: OPENAI_API_KEY not found');
    }
});