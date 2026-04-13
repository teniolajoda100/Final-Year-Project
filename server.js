const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const mammoth = require('mammoth');
const OpenAI = require('openai');
require('dotenv').config();

// Import CV analysis functions
const {
    calculateProficiency,
    detectCategory,
    extractEducationYears,
    extractIndustryYears,
    extractPDFText
} = require('./cvAnalysis');

// Import database operations
const {
    saveCVAnalysis,
    getLatestCVAnalysis,
    getAllCVAnalyses,
    getCVAnalysisById,
    deleteCVAnalysis,
    saveJobComparison,
    pool
} = require('./dbOperations');

// Import job analysis functions
const {
    getCommonJobTitles,
    analyzeJobRequirements,
    compareSkillsWithJob,
    calculateCareerReadiness,
    calculateExperienceRelevance
} = require('./jobAnalysis');

// Import recruiter routes
const recruiterRoutes = require('./recruiterRoutes');

const app = express();
const PORT = 3000;

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
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname)));

// Mount recruiter routes
app.use('/api/recruiter', recruiterRoutes);

/* ================================
   HELPER FUNCTIONS
   ================================ */

// LLM assisted skill proficiency analysis
async function analyzeSkillProficiency(skills, cvText, industryYears, educationYears) {
    try {
        const prompt = `You are an expert CV analyst. Analyze the proficiency level for each skill based on the CV text.

For each skill, determine:
1. Proficiency Score (1-10): Based on depth of experience, project complexity, and demonstrated mastery
2. Bloom's Taxonomy Level: Remember, Understand, Apply, Analyze, Evaluate, or Create
3. Evidence: Specific phrases from CV that demonstrate this skill
4. Basis: Brief explanation of why this score was given

Scoring Guidelines:
- 1-3 (Beginner): Basic knowledge, mentioned in passing, no concrete examples
- 4-6 (Intermediate): Some practical experience, used in projects, moderate complexity
- 7-8 (Advanced): Extensive experience, led projects, solved complex problems
- 9-10 (Expert): Mastery level, created solutions, taught others, innovated

Years of Experience: ${industryYears} industry, ${educationYears} education

Skills to analyze: ${JSON.stringify(skills)}

CV Text (excerpt): ${cvText.substring(0, 2500)}

Respond with a JSON object with "skills" key containing an array:
{
  "skills": [
    {
      "skill": "skill name",
      "score": 7,
      "bloomLevel": "Apply",
      "evidence": "specific quote from CV",
      "basis": "explanation of score"
    }
  ]
}`;

        const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: 'json_object' },
            temperature: 0.3
        });

        const result = JSON.parse(response.choices[0].message.content);
        
        let analysisArray = [];
        
        if (Array.isArray(result)) {
            analysisArray = result;
        } else if (result.skills && Array.isArray(result.skills)) {
            analysisArray = result.skills;
        } else if (result.analyses && Array.isArray(result.analyses)) {
            analysisArray = result.analyses;
        } else {
            const values = Object.values(result);
            const firstArray = values.find(v => Array.isArray(v));
            analysisArray = firstArray || [];
        }
        
        console.log(`LLM Analysis returned ${analysisArray.length} skill assessments`);
        return analysisArray;
        
    } catch (error) {
        console.error('Error in LLM skill analysis:', error);
        return [];
    }
}

/* ================================
   AUTHENTICATION ROUTES
   ================================ */

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

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
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Error</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-danger" role="alert">
                            <h4 class="alert-heading">Login Failed</h4>
                            <p>Invalid email or password. Please try again.</p>
                            <hr>
                            <a href="/login" class="btn btn-primary">Back to Login</a>
                        </div>
                    </div>
                </body>
                </html>
            `);
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (!match) {
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Error</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-danger" role="alert">
                            <h4 class="alert-heading">Login Failed</h4>
                            <p>Invalid email or password. Please try again.</p>
                            <hr>
                            <a href="/login" class="btn btn-primary">Back to Login</a>
                        </div>
                    </div>
                </body>
                </html>
            `);
        }

        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.fullName = user.full_name;
        req.session.email = user.email;

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
        req.session.email = email;

        res.redirect('/dashboard');

    } catch (err) {
        console.error(err);
        res.status(500).send('Error creating account');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Logout failed');
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

app.get('/profile-data', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    res.json({
        fullName: req.session.fullName,
        role: req.session.role,
        email: req.session.email
    });
});

/* ================================
   DASHBOARD ROUTES (FIXED - SINGLE ROUTE)
   ================================ */

app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    const role = req.session.role || 'student';

    // Recruiters always go to recruiter dashboard
    if (role === 'recruiter') {
        return res.sendFile(path.join(__dirname, 'dashboard-recruiter.html'));
    }

    // Working professionals always go to professional dashboard
    if (role === 'professional') {
        return res.sendFile(path.join(__dirname, 'dashboard-professional.html'));
    }

    // Students/graduates - check for CV analysis
    try {
        const result = await pool.query(
            'SELECT id FROM cv_analyses WHERE user_id = $1 ORDER BY analyzed_at DESC LIMIT 1',
            [req.session.userId]
        );

        if (result.rows.length > 0) {
            return res.sendFile(path.join(__dirname, 'dashboard.html'));
        } else {
            return res.redirect('/upload');
        }
    } catch (err) {
        console.error('Error checking CV:', err);
        return res.redirect('/upload');
    }
});

app.get('/candidate-analysis.html', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/signup');
    }
    if (req.session.role !== 'recruiter') {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'candidate-analysis.html'));
});

app.get('/upload', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/signup');
    }
    res.sendFile(path.join(__dirname, 'dashboard-user.html'));
});

/* ================================
   USER CV ANALYSIS ROUTES
   ================================ */

app.get('/api/latest-cv-analysis', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const result = await getLatestCVAnalysis(req.session.userId);
    res.json(result);
});

app.get('/api/cv-analyses-history', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const result = await getAllCVAnalyses(req.session.userId);
    res.json(result);
});

app.get('/api/cv-analysis/:id', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const result = await getCVAnalysisById(req.session.userId, req.params.id);
    res.json(result);
});

app.post('/analyze', upload.single('cvFile'), async (req, res) => {
    try {
        if (!req.file) return res.json({ error: 'No file uploaded' });

        if (!openai || !process.env.OPENAI_API_KEY) {
            return res.json({ error: 'LLM API key not configured' });
        }

        let text = req.file.originalname.toLowerCase().endsWith('.pdf') 
            ? await extractPDFText(req.file.path)
            : (await mammoth.extractRawText({ path: req.file.path })).value;
        
        fs.unlinkSync(req.file.path);
        
        if (!text || text.length < 10) {
            return res.json({ error: 'Could not extract text from file' });
        }

        const extractionResponse = await openai.chat.completions.create({
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

        const data = JSON.parse(extractionResponse.choices[0].message.content);
        
        const educationYears = extractEducationYears(data.education || []);
        const industryYears = extractIndustryYears(data.experience || []);
        
        console.log(`\n Analyzing CV: ${data.skills?.length || 0} skills, ${industryYears} years industry experience`);

        console.log(' Step 1: LLM analyzing skills...');
        const llmAnalysis = await analyzeSkillProficiency(
            data.skills || [], 
            text, 
            industryYears, 
            educationYears
        );

        console.log('  Step 2: Processing with hybrid scoring...');
        const skillsWithProficiency = (data.skills || []).map(skillName => {
            const categoryInfo = detectCategory(skillName);
            
            const llmSkill = llmAnalysis.find(s => 
                s.skill?.toLowerCase() === skillName.toLowerCase()
            );

            let finalScore, bloomLevel, evidence, basis, confidence;

            if (llmSkill) {
                finalScore = llmSkill.score;
                bloomLevel = llmSkill.bloomLevel || 'Apply';
                evidence = llmSkill.evidence || '';
                basis = llmSkill.basis || 'LLM-analyzed';
                confidence = 'High';
                
                console.log(`  LLM scored "${skillName}": ${finalScore}/10 (${bloomLevel})`);
            } else {
                const proficiency = calculateProficiency(skillName, text, industryYears, educationYears);
                finalScore = proficiency.score;
                bloomLevel = proficiency.bloomLevel || 'Remember';
                evidence = '';
                basis = proficiency.basis;
                confidence = proficiency.confidence;
                
                console.log(`   Rule-based scored "${skillName}": ${finalScore}/10`);
            }

            let experienceBoost = 0;
            if (industryYears >= 5) {
                experienceBoost = Math.min(1, industryYears / 10);
            }

            finalScore = Math.min(10, finalScore + experienceBoost);

            return {
                name: skillName,
                score: parseFloat(finalScore.toFixed(1)),
                confidence: confidence,
                basis: basis,
                bloomLevel: bloomLevel,
                category: categoryInfo.category,
                skillType: categoryInfo.type,
                weight: categoryInfo.weight,
                evidenceCount: evidence ? 1 : 0,
                evidencePieces: evidence ? [evidence] : [],
                skillSource: llmSkill ? 'LLM-analyzed' : 'Rule-based',
                method: llmSkill ? 'AI Assessment' : 'Pattern Matching',
                supported: evidence.length > 0 || finalScore >= 5,
                weightedScore: (finalScore * categoryInfo.weight).toFixed(2)
            };
        });
        
        skillsWithProficiency.sort((a, b) => b.weightedScore - a.weightedScore);
        
        const skillsByType = {
            technical: skillsWithProficiency.filter(s => s.skillType === 'technical').length,
            soft: skillsWithProficiency.filter(s => s.skillType === 'soft').length,
            business: skillsWithProficiency.filter(s => s.skillType === 'business').length
        };

        const analysisData = {
            skills: skillsWithProficiency,
            education: data.education || [],
            experience: data.experience || [],
            educationYears: educationYears,
            industryYears: industryYears,
            skillsByType: skillsByType,
            cvText: text,
            summary: {
                totalSkills: skillsWithProficiency.length,
                strongSkills: skillsWithProficiency.filter(s => s.score >= 7).length,
                supportedSkills: skillsWithProficiency.filter(s => s.supported).length,
                averageScore: (skillsWithProficiency.reduce((acc, s) => acc + s.score, 0) / skillsWithProficiency.length).toFixed(2)
            }
        };

        console.log(`✅ Analysis complete!\n`);

        if (req.session.userId) {
            const saveResult = await saveCVAnalysis(req.session.userId, analysisData);
            if (saveResult.success) {
                console.log(`💾 CV analysis saved for user ${req.session.userId}`);
            }
        }
        
        res.json(analysisData);
        
    } catch (error) {
        console.error('Error analyzing CV:', error);
        res.json({ error: error.message });
    }
});

/* ================================
   JOB ANALYSIS ROUTES
   ================================ */

app.get('/api/job-titles', (req, res) => {
    res.json({ jobTitles: getCommonJobTitles() });
});

app.post('/api/analyze-job', async (req, res) => {
    const { jobTitle } = req.body;

    if (!jobTitle) {
        return res.json({ error: 'Job title is required' });
    }

    const analysis = await analyzeJobRequirements(jobTitle);
    res.json(analysis);
});

app.post('/api/compare-with-job', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const { jobTitle } = req.body;

    if (!jobTitle) {
        return res.json({ error: 'Job title is required' });
    }

    try {
        const cvResult = await getLatestCVAnalysis(req.session.userId);
        
        if (!cvResult.success || !cvResult.hasAnalysis) {
            return res.json({ error: 'No CV analysis found. Please upload your CV first.' });
        }

        const userData = cvResult.data;
        
        const comparison = await compareSkillsWithJob(
            userData.skills, 
            jobTitle,
            userData.cvText,
            userData.experience,
            userData.education
        );

        if (comparison.error) {
            return res.json({ error: comparison.error });
        }

        const readinessResult = calculateCareerReadiness(
            userData.skills,
            userData.industryYears,
            userData.educationYears,
            comparison
        );

        const relevanceResult = calculateExperienceRelevance(
            userData.industryYears,
            userData.educationYears,
            userData.skills,
            comparison
        );

        const comparisonToSave = {
            jobTitle,
            jobRequirements: comparison.jobRequirements,
            skillComparison: comparison.skillComparison,
            metrics: { 
                readinessScore: readinessResult.score, 
                relevanceScore: relevanceResult.score 
            }
        };

        const saveResult = await saveJobComparison(
            req.session.userId, 
            userData.analysisId, 
            comparisonToSave
        );

        if (saveResult.success) {
            console.log(`✅ Job comparison saved for user ${req.session.userId}`);
        }

        res.json({
            ...comparison,
            metrics: {
                readiness: readinessResult,
                relevance: relevanceResult
            },
            userData: {
                totalSkills: userData.skills.length,
                strongSkills: userData.skills.filter(s => s.score >= 7).length,
                industryYears: userData.industryYears,
                educationYears: userData.educationYears
            },
            saved: saveResult.success
        });

    } catch (error) {
        console.error('Error in job comparison:', error);
        res.json({ error: error.message });
    }
});

/* ================================
   OTHER ROUTES
   ================================ */


app.get('/results', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/signup');
    }
    
    // Route based on role
    if (req.session.role === 'professional') {
        return res.sendFile(path.join(__dirname, 'results-professional.html'));
    }
    
    // Default student/graduate results
    res.sendFile(path.join(__dirname, 'results.html'));
});
app.get('/session-info', (req, res) => {
    if (req.session.userId) {
        return res.json({
            loggedIn: true,
            fullName: req.session.fullName,
            role: req.session.role
        });
    }
    res.json({ loggedIn: false });
});

app.get('/profile', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'profile.html'));
});

app.listen(PORT, () => {
    console.log(`✅ CVision running at http://localhost:${PORT}`);
    console.log(`   Student Dashboard: /dashboard (student/graduate role)`);
    console.log(`   Professional Dashboard: /dashboard (professional role)`);
    console.log(`   Recruiter Dashboard: /dashboard (recruiter role)`);
    console.log(`   API Routes: /api/recruiter/*`);
    if (!process.env.OPENAI_API_KEY) {
        console.log('⚠️  Warning: OPENAI_API_KEY not found');
    }
});