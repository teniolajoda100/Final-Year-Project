const OpenAI = require('openai');
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ================================
   COMMON JOB TITLES DATABASE
   ================================ */

function getCommonJobTitles() {
    return [
        'Software Engineer',
        'Data Scientist',
        'Product Manager',
        'Marketing Manager',
        'Business Analyst',
        'UX/UI Designer',
        'DevOps Engineer',
        'Full Stack Developer',
        'Frontend Developer',
        'Backend Developer',
        'Mobile Developer',
        'Project Manager',
        'Sales Manager',
        'Financial Analyst',
        'HR Manager',
        'Operations Manager',
        'Customer Success Manager',
        'Content Writer',
        'Graphic Designer',
        'Machine Learning Engineer',
        'Cloud Architect',
        'Cybersecurity Analyst',
        'Digital Marketing Specialist',
        'SEO Specialist',
        'Account Manager',
        'Recruiter',
        'Business Development Manager',
        'Quality Assurance Engineer',
        'System Administrator',
        'Network Engineer'
    ];
}

/* ================================
   JOB REQUIREMENTS ANALYSIS
   ================================ */

// FIXED: Analyze job requirements using OpenAI
async function analyzeJobRequirements(jobTitle) {
    if (!openai || !process.env.OPENAI_API_KEY) {
        console.error('❌ OpenAI not configured');
        return null;
    }

    try {
        console.log(`\n🔍 Analyzing job requirements for: ${jobTitle}`);

        const prompt = `You are a career expert. Analyze the typical requirements for the job title: "${jobTitle}"

Provide a comprehensive breakdown in JSON format:
{
  "jobTitle": "${jobTitle}",
  "requiredSkills": ["skill1", "skill2", "skill3", "skill4", "skill5"],
  "niceToHaveSkills": ["skill6", "skill7", "skill8"],
  "experienceLevel": "Entry-level",
  "typicalYearsRequired": 2,
  "keyResponsibilities": ["responsibility1", "responsibility2"],
  "industryContext": "Brief context about this role"
}

Be specific and realistic. Include 8-12 required skills and 5-8 nice-to-have skills.
experienceLevel must be one of: "Entry-level", "Mid-level", "Senior", "Lead", "Executive"`;

        const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: 'json_object' },
            temperature: 0.3,
            max_tokens: 1000
        });

        const analysis = JSON.parse(response.choices[0].message.content);
        
        // Validate response
        if (!analysis.requiredSkills || !Array.isArray(analysis.requiredSkills)) {
            console.error('❌ Invalid job analysis response');
            return null;
        }

        console.log(`✅ Job analysis complete: ${analysis.requiredSkills.length} required skills identified`);
        
        return analysis;

    } catch (error) {
        console.error('❌ Error analyzing job requirements:', error.message);
        return null;
    }
}

/* ================================
   SKILL COMPARISON
   ================================ */

// IMPROVED: Fuzzy skill matching helper
function skillsMatch(userSkill, jobSkill) {
    const normalize = (str) => str.toLowerCase().trim().replace(/[^a-z0-9]/g, '');
    
    const userNorm = normalize(userSkill);
    const jobNorm = normalize(jobSkill);
    
    // Exact match
    if (userNorm === jobNorm) return true;
    
    // Contains match
    if (userNorm.includes(jobNorm) || jobNorm.includes(userNorm)) return true;
    
    // Common aliases and variations
    const aliases = {
        'js': 'javascript',
        'javascript': 'js',
        'ts': 'typescript',
        'typescript': 'ts',
        'py': 'python',
        'python': 'py',
        'reactjs': 'react',
        'react': 'reactjs',
        'nodejs': 'node',
        'node': 'nodejs',
        'nosql': 'mongodb',
        'mongodb': 'nosql',
        'aws': 'amazon web services',
        'amazon web services': 'aws',
        'gcp': 'google cloud',
        'google cloud': 'gcp',
        'ml': 'machine learning',
        'machine learning': 'ml',
        'ai': 'artificial intelligence',
        'artificial intelligence': 'ai',
        'rest': 'restful',
        'restful': 'rest',
        'api': 'apis',
        'apis': 'api'
    };
    
    // Check aliases
    if (aliases[userNorm] && normalize(aliases[userNorm]) === jobNorm) return true;
    if (aliases[jobNorm] && normalize(aliases[jobNorm]) === userNorm) return true;
    
    // Framework/language family matching
    const families = [
        ['react', 'reactjs', 'react.js', 'reactnative'],
        ['vue', 'vuejs', 'vue.js'],
        ['angular', 'angularjs', 'angular.js'],
        ['node', 'nodejs', 'node.js', 'express', 'expressjs'],
        ['python', 'django', 'flask'],
        ['java', 'spring', 'springboot'],
        ['javascript', 'js', 'ecmascript', 'es6'],
        ['sql', 'mysql', 'postgresql', 'database'],
        ['docker', 'kubernetes', 'containerization'],
        ['aws', 'ec2', 's3', 'lambda', 'cloud'],
        ['git', 'github', 'gitlab', 'version control']
    ];
    
    for (const family of families) {
        if (family.includes(userNorm) && family.includes(jobNorm)) {
            return true;
        }
    }
    
    return false;
}

// Enhanced skill comparison
async function compareSkillsWithJob(userSkills, jobTitle, cvText, experience, education) {
    try {
        // Get job requirements
        const jobReqs = await analyzeJobRequirements(jobTitle);
        
        if (!jobReqs) {
            return {
                error: 'Could not analyze job requirements. Please try a different job title or check your internet connection.'
            };
        }

        const requiredSkills = jobReqs.requiredSkills || [];
        const niceToHaveSkills = jobReqs.niceToHaveSkills || [];

        // Match user skills with job requirements
        const matchedSkills = [];
        const missingCriticalSkills = [];
        const niceToHaveMatched = [];

        requiredSkills.forEach(reqSkill => {
            const userSkill = userSkills.find(s => 
                skillsMatch(s.name, reqSkill)
            );

            if (userSkill) {
                matchedSkills.push({
                    skill: reqSkill,
                    userScore: userSkill.score,
                    required: true
                });
            } else {
                missingCriticalSkills.push(reqSkill);
            }
        });

        niceToHaveSkills.forEach(niceSkill => {
            const userSkill = userSkills.find(s => 
                skillsMatch(s.name, niceSkill)
            );

            if (userSkill) {
                niceToHaveMatched.push({
                    skill: niceSkill,
                    userScore: userSkill.score
                });
            }
        });

        // Calculate match percentage
        const matchPercentage = requiredSkills.length > 0
            ? Math.round((matchedSkills.length / requiredSkills.length) * 100)
            : 0;

        console.log(`✅ Skill comparison complete: ${matchPercentage}% match`);

        return {
            jobTitle: jobTitle,
            jobRequirements: jobReqs,
            skillComparison: {
                matchedSkills: matchedSkills,
                missingCriticalSkills: missingCriticalSkills,
                niceToHaveMatched: niceToHaveMatched,
                matchPercentage: matchPercentage,
                totalRequired: requiredSkills.length,
                totalMatched: matchedSkills.length,
                totalMissing: missingCriticalSkills.length
            }
        };

    } catch (error) {
        console.error('❌ Error in skill comparison:', error);
        return {
            error: 'Error comparing skills with job requirements: ' + error.message
        };
    }
}

/* ================================
   CAREER READINESS CALCULATION
   ================================ */

function calculateCareerReadiness(userSkills, industryYears, educationYears, comparison) {
    const skillComparison = comparison.skillComparison || {};
    const jobReqs = comparison.jobRequirements || {};
    
    const matchPercentage = skillComparison.matchPercentage || 0;
    const totalRequired = skillComparison.totalRequired || 1;
    const totalMatched = skillComparison.totalMatched || 0;
    const missingCount = skillComparison.totalMissing || 0;
    
    const typicalYears = jobReqs.typicalYearsRequired || 0;
    const experienceLevel = jobReqs.experienceLevel || 'Entry-level';

    let score = 0;
    let reasons = [];

    // Factor 1: Skill Match (40%)
    score += matchPercentage * 0.4;
    if (matchPercentage >= 80) {
        reasons.push(`✓ Excellent skill match (${matchPercentage}%) - you have most required skills`);
    } else if (matchPercentage >= 60) {
        reasons.push(`✓ Good skill match (${matchPercentage}%) - you meet majority of requirements`);
    } else if (matchPercentage >= 40) {
        reasons.push(`⚠ Moderate skill match (${matchPercentage}%) - some gaps to address`);
    } else {
        reasons.push(`✗ Low skill match (${matchPercentage}%) - significant upskilling needed`);
    }

    // Factor 2: Experience Match (35%)
    let experienceScore = 0;
    if (industryYears >= typicalYears) {
        experienceScore = 35;
        reasons.push(`✓ Experience exceeds requirement (${industryYears} years vs ${typicalYears} required)`);
    } else if (industryYears >= typicalYears * 0.75) {
        experienceScore = 28;
        reasons.push(`✓ Close to experience requirement (${industryYears} years vs ${typicalYears} required)`);
    } else if (industryYears >= typicalYears * 0.5) {
        experienceScore = 20;
        reasons.push(`⚠ Below experience requirement (${industryYears} years vs ${typicalYears} required)`);
    } else {
        experienceScore = 10;
        reasons.push(`✗ Significantly under experience requirement (${industryYears} years vs ${typicalYears} required)`);
    }
    score += experienceScore;

    // Factor 3: Skill Quality (25%)
    const averageSkillScore = userSkills.reduce((sum, s) => sum + s.score, 0) / (userSkills.length || 1);
    const qualityScore = (averageSkillScore / 10) * 25;
    score += qualityScore;
    
    if (averageSkillScore >= 7) {
        reasons.push(`✓ High skill proficiency (${averageSkillScore.toFixed(1)}/10 average)`);
    } else if (averageSkillScore >= 5) {
        reasons.push(`⚠ Moderate skill proficiency (${averageSkillScore.toFixed(1)}/10 average)`);
    } else {
        reasons.push(`✗ Skills need development (${averageSkillScore.toFixed(1)}/10 average)`);
    }

    // Determine verdict
    let verdict = '';
    if (score >= 80) {
        verdict = 'Highly Ready - Apply with confidence!';
    } else if (score >= 65) {
        verdict = 'Ready - Strong candidate for this role';
    } else if (score >= 50) {
        verdict = 'Moderately Ready - Address gaps first';
    } else if (score >= 35) {
        verdict = 'Not Quite Ready - Significant preparation needed';
    } else {
        verdict = 'Not Ready - Consider entry-level roles first';
    }

    return {
        score: Math.round(score),
        reasons: reasons,
        verdict: verdict,
        missingSkills: skillComparison.missingCriticalSkills || []
    };
}

/* ================================
   EXPERIENCE RELEVANCE CALCULATION
   ================================ */

function calculateExperienceRelevance(industryYears, educationYears, userSkills, comparison) {
    const skillComparison = comparison.skillComparison || {};
    const jobReqs = comparison.jobRequirements || {};
    
    const matchPercentage = skillComparison.matchPercentage || 0;
    const typicalYears = jobReqs.typicalYearsRequired || 0;

    let score = 0;
    let reasons = [];

    // Factor 1: Years of Experience (50%)
    if (industryYears >= typicalYears * 1.5) {
        score += 50;
        reasons.push(`✓ Extensive experience (${industryYears} years) - well above requirement`);
    } else if (industryYears >= typicalYears) {
        score += 45;
        reasons.push(`✓ Sufficient experience (${industryYears} years) - meets requirement`);
    } else if (industryYears >= typicalYears * 0.75) {
        score += 35;
        reasons.push(`⚠ Slightly under required experience (${industryYears} years vs ${typicalYears} needed)`);
    } else if (industryYears > 0) {
        score += 20;
        reasons.push(`✗ Below required experience (${industryYears} years vs ${typicalYears} needed)`);
    } else {
        score += 5;
        reasons.push(`✗ No industry experience - consider internships first`);
    }

    // Factor 2: Skill Relevance (35%)
    const relevanceScore = (matchPercentage / 100) * 35;
    score += relevanceScore;
    
    if (matchPercentage >= 75) {
        reasons.push(`✓ Skills highly relevant to role (${matchPercentage}% match)`);
    } else if (matchPercentage >= 50) {
        reasons.push(`⚠ Skills moderately relevant (${matchPercentage}% match)`);
    } else {
        reasons.push(`✗ Skills not closely aligned (${matchPercentage}% match)`);
    }

    // Factor 3: Education Background (15%)
    if (educationYears >= 4) {
        score += 15;
        reasons.push(`✓ Strong educational background (${educationYears} years)`);
    } else if (educationYears >= 2) {
        score += 10;
        reasons.push(`⚠ Moderate educational background (${educationYears} years)`);
    } else if (educationYears > 0) {
        score += 5;
        reasons.push(`⚠ Limited formal education (${educationYears} years)`);
    }

    // Determine verdict
    let verdict = '';
    if (score >= 80) {
        verdict = 'Highly Relevant - Excellent match!';
    } else if (score >= 65) {
        verdict = 'Relevant - Good fit for role';
    } else if (score >= 50) {
        verdict = 'Moderately Relevant - Some gaps exist';
    } else if (score >= 35) {
        verdict = 'Somewhat Relevant - Consider upskilling';
    } else {
        verdict = 'Not Relevant - Significant experience gap';
    }

    return {
        score: Math.round(score),
        reasons: reasons,
        verdict: verdict
    };
}

module.exports = {
    getCommonJobTitles,
    analyzeJobRequirements,
    compareSkillsWithJob,
    calculateCareerReadiness,
    calculateExperienceRelevance,
    skillsMatch
};