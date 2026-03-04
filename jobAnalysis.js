const OpenAI = require('openai');
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ================================
   SKILL CATEGORIZATION HELPERS
   ================================ */

// Rule-based categorization (fallback)
function categorizeSkillRuleBased(skillName) {
    const skill = skillName.toLowerCase();
    
    // Technical Skills
    const technicalKeywords = [
        // Programming Languages
        'javascript', 'python', 'java', 'c++', 'c#', 'ruby', 'php', 'swift', 'kotlin', 'go', 'rust', 'typescript', 'sql', 'r', 'matlab', 'scala', 'perl',
        // Frameworks & Libraries
        'react', 'angular', 'vue', 'node', 'express', 'django', 'flask', 'spring', 'laravel', 'rails', 'next.js', 'nuxt', 'svelte',
        // Databases
        'mysql', 'postgresql', 'mongodb', 'redis', 'cassandra', 'oracle', 'sql server', 'dynamodb', 'firebase',
        // DevOps & Cloud
        'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'jenkins', 'gitlab', 'github actions', 'terraform', 'ansible',
        // Tools & Technologies
        'git', 'linux', 'api', 'rest', 'graphql', 'microservices', 'testing', 'ci/cd', 'agile', 'scrum',
        // Data & AI
        'machine learning', 'deep learning', 'ai', 'data analysis', 'pandas', 'numpy', 'tensorflow', 'pytorch', 'scikit-learn',
        // Other Technical
        'html', 'css', 'sass', 'webpack', 'babel', 'elasticsearch', 'nginx', 'apache', 'security', 'encryption', 'blockchain'
    ];
    
    // Soft Skills
    const softKeywords = [
        'communication', 'leadership', 'teamwork', 'collaboration', 'problem solving', 'critical thinking',
        'creativity', 'adaptability', 'time management', 'organization', 'presentation', 'negotiation',
        'conflict resolution', 'emotional intelligence', 'empathy', 'listening', 'mentoring', 'coaching',
        'interpersonal', 'public speaking', 'networking', 'relationship building', 'persuasion', 'influence'
    ];
    
    // Business Skills
    const businessKeywords = [
        'project management', 'product management', 'business analysis', 'strategy', 'marketing',
        'sales', 'customer service', 'financial analysis', 'budgeting', 'planning', 'forecasting',
        'analytics', 'reporting', 'stakeholder management', 'requirements gathering', 'risk management',
        'vendor management', 'contract negotiation', 'business development', 'operations', 'process improvement'
    ];
    
    // Domain-Specific Skills
    const domainKeywords = [
        'design', 'ui', 'ux', 'photoshop', 'figma', 'sketch', 'illustrator', 'prototyping',
        'healthcare', 'medical', 'finance', 'accounting', 'legal', 'compliance', 'audit'
    ];
    
    // Check technical first (most specific)
    if (technicalKeywords.some(keyword => skill.includes(keyword))) {
        return 'technical';
    }
    
    // Check domain-specific
    if (domainKeywords.some(keyword => skill.includes(keyword))) {
        return 'domain';
    }
    
    // Check business skills
    if (businessKeywords.some(keyword => skill.includes(keyword))) {
        return 'business';
    }
    
    // Check soft skills
    if (softKeywords.some(keyword => skill.includes(keyword))) {
        return 'soft';
    }
    
    // Default: if unclear, categorize as soft skill
    return 'soft';
}

/* ================================
   JOB MATCHING & ANALYSIS
   ================================ */

// Get common job titles for dropdown
function getCommonJobTitles() {
    return [
        // Software Development
        "Software Engineer",
        "Frontend Developer",
        "Backend Developer",
        "Full Stack Developer",
        "Mobile Developer",
        "DevOps Engineer",
        "Machine Learning Engineer",
        "Data Scientist",
        "Data Engineer",
        "AI Engineer",
        
        // Design & Creative
        "UI/UX Designer",
        "Graphic Designer",
        "Product Designer",
        "Web Designer",
        
        // Management
        "Product Manager",
        "Project Manager",
        "Engineering Manager",
        "Technical Lead",
        "Scrum Master",
        
        // Business
        "Business Analyst",
        "Data Analyst",
        "Marketing Manager",
        "Sales Manager",
        
        // Other Technical
        "Cloud Architect",
        "Security Engineer",
        "QA Engineer",
        "Database Administrator",
        "Systems Administrator"
    ];
}

// Analyze job requirements using LLM
async function analyzeJobRequirements(jobTitle) {
    try {
        const prompt = `You are a job market expert. Analyze the typical requirements for the job title: "${jobTitle}"

Provide a JSON response with:
1. requiredSkills: Array of essential skills (10-15 skills) - be SPECIFIC with technology names (e.g., "JavaScript" not "programming", "React" not "frameworks")
2. niceToHaveSkills: Array of beneficial but not required skills (5-10 skills)
3. experienceLevel: "Entry", "Mid", "Senior", or "Lead"
4. typicalYearsRequired: Number of years typically required
5. keyResponsibilities: Array of 3-5 main responsibilities
6. industryContext: Brief description of where this role fits

IMPORTANT: List specific programming languages, frameworks, and tools. Don't use generic terms like "programming" or "coding".

Response format:
{
  "requiredSkills": ["JavaScript", "React", "Node.js", "Git", "REST APIs"],
  "niceToHaveSkills": ["TypeScript", "Docker", "AWS"],
  "experienceLevel": "Mid",
  "typicalYearsRequired": 3,
  "keyResponsibilities": ["resp1", "resp2"],
  "industryContext": "brief description"
}`;

        const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: 'json_object' },
            temperature: 0.3
        });

        const result = JSON.parse(response.choices[0].message.content);
        console.log(`✅ Job analysis complete for: ${jobTitle}`);
        return result;

    } catch (error) {
        console.error('Error analyzing job requirements:', error);
        return null;
    }
}

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

// NEW: Deep CV analysis using LLM
async function analyzeCVForJobMatch(cvText, experience, education, jobRequirements, jobTitle) {
    try {
        const prompt = `You are a HARSH and REALISTIC recruiter. Analyze this CV against the job requirements and be BRUTALLY HONEST.

Job Title: ${jobTitle}
Required Skills: ${JSON.stringify(jobRequirements.requiredSkills)}
Nice-to-Have Skills: ${JSON.stringify(jobRequirements.niceToHaveSkills)}
Experience Level Required: ${jobRequirements.experienceLevel}
Years Required: ${jobRequirements.typicalYearsRequired}

CV Text: ${cvText.substring(0, 4000)}
Experience: ${JSON.stringify(experience)}
Education: ${JSON.stringify(education)}

Be HARSH and REALISTIC. Analyze:
1. Which skills they ACTUALLY have (not just mentioned, but demonstrated)
2. What critical skills they're MISSING
3. Experience gaps (internships, professional work, projects)
4. Whether their experience level matches the job

Respond with JSON:
{
  "foundSkills": [
    {"skill": "JavaScript", "proficiency": 8, "evidence": "3 years building React apps"}
  ],
  "missingCritical": ["Docker", "AWS"],
  "missingNiceToHave": ["TypeScript"],
  "matchPercentage": 60,
  "harshFeedback": {
    "experienceGaps": ["No internship experience", "Lack of production deployment experience"],
    "skillGaps": ["Missing critical DevOps skills", "No cloud platform experience"],
    "strengthAreas": ["Strong frontend skills", "Good React knowledge"],
    "weeknessAreas": ["No backend experience", "Missing infrastructure knowledge"],
    "readinessAssessment": "NOT READY - Missing 40% of required skills and lacks professional experience",
    "recommendedActions": ["Complete AWS certification", "Build and deploy 2-3 full-stack projects", "Gain internship experience"]
  }
}

Be HARSH but FAIR. If they're not qualified, say so clearly.`;

        const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: 'json_object' },
            temperature: 0.3,
            max_tokens: 1500
        });

        const result = JSON.parse(response.choices[0].message.content);
        return result;

    } catch (error) {
        console.error('Error in deep CV analysis:', error);
        return null;
    }
}

// IMPROVED: Compare user skills with job requirements using CV text
async function compareSkillsWithJob(userSkills, jobTitle, cvText, experience, education) {
    try {
        // First, get job requirements
        const jobReqs = await analyzeJobRequirements(jobTitle);
        if (!jobReqs) {
            return { error: 'Could not analyze job requirements' };
        }

        // Try deep LLM analysis if CV text is available
        if (cvText && cvText.length > 100) {
            console.log('🔍 Performing HARSH deep CV analysis...');
            const deepAnalysis = await analyzeCVForJobMatch(
                cvText, 
                experience, 
                education, 
                jobReqs, 
                jobTitle
            );
            
            if (deepAnalysis && deepAnalysis.foundSkills) {
                console.log(`✅ Deep analysis: ${deepAnalysis.matchPercentage}% match`);
                
                const matchedSkills = deepAnalysis.foundSkills.map(s => ({
                    skill: s.skill,
                    userScore: s.proficiency,
                    importance: 'critical',
                    userSkillName: s.skill,
                    evidence: s.evidence || ''
                }));

                // Generate HARSH recommendations
                const recommendations = [];
                
                if (deepAnalysis.matchPercentage < 50) {
                    recommendations.push(`⚠️ CRITICAL: You are significantly underqualified for this role (${deepAnalysis.matchPercentage}% match)`);
                    recommendations.push(`You are missing ${deepAnalysis.missingCritical.length} critical skills required for this position`);
                } else if (deepAnalysis.matchPercentage < 70) {
                    recommendations.push(`⚠️ WARNING: You meet some requirements but have significant gaps (${deepAnalysis.matchPercentage}% match)`);
                }

                if (deepAnalysis.missingCritical && deepAnalysis.missingCritical.length > 0) {
                    recommendations.push(`❌ MISSING CRITICAL SKILLS: ${deepAnalysis.missingCritical.join(', ')}`);
                }

                if (deepAnalysis.harshFeedback?.experienceGaps && deepAnalysis.harshFeedback.experienceGaps.length > 0) {
                    recommendations.push(`📉 EXPERIENCE GAPS: ${deepAnalysis.harshFeedback.experienceGaps.join(', ')}`);
                }

                if (deepAnalysis.harshFeedback?.recommendedActions) {
                    recommendations.push(...deepAnalysis.harshFeedback.recommendedActions);
                }

                const comparison = {
                    matchedSkills: matchedSkills,
                    missingCriticalSkills: deepAnalysis.missingCritical || [],
                    missingNiceToHave: deepAnalysis.missingNiceToHave || [],
                    overqualifiedSkills: [],
                    matchPercentage: deepAnalysis.matchPercentage || 0,
                    experienceGap: deepAnalysis.harshFeedback?.readinessAssessment || `This ${jobReqs.experienceLevel}-level role typically requires ${jobReqs.typicalYearsRequired} years of experience.`,
                    recommendations: recommendations,
                    strengthAreas: deepAnalysis.harshFeedback?.strengthAreas || [],
                    weaknessAreas: deepAnalysis.harshFeedback?.weeknessAreas || [],
                    // NEW: Detailed breakdowns for metrics
                    detailedFeedback: {
                        experienceGaps: deepAnalysis.harshFeedback?.experienceGaps || [],
                        skillGaps: deepAnalysis.harshFeedback?.skillGaps || [],
                        readinessAssessment: deepAnalysis.harshFeedback?.readinessAssessment || '',
                        strengthAreas: deepAnalysis.harshFeedback?.strengthAreas || [],
                        weeknessAreas: deepAnalysis.harshFeedback?.weeknessAreas || []
                    }
                };

                return {
                    jobRequirements: jobReqs,
                    skillComparison: comparison,
                    jobTitle: jobTitle,
                    deepAnalysis: true
                };
            }
        }

        // Fallback to fuzzy matching
        console.log('⚠️ Using fallback fuzzy matching');
        const matchedSkills = [];
        const requiredSkillsSet = new Set(jobReqs.requiredSkills.map(s => s.toLowerCase()));
        const niceToHaveSet = new Set(jobReqs.niceToHaveSkills.map(s => s.toLowerCase()));
        
        userSkills.forEach(userSkill => {
            for (const reqSkill of jobReqs.requiredSkills) {
                if (skillsMatch(userSkill.name, reqSkill)) {
                    matchedSkills.push({
                        skill: reqSkill,
                        userScore: userSkill.score,
                        importance: 'critical',
                        userSkillName: userSkill.name
                    });
                    requiredSkillsSet.delete(reqSkill.toLowerCase());
                    break;
                }
            }
            
            for (const niceSkill of jobReqs.niceToHaveSkills) {
                if (skillsMatch(userSkill.name, niceSkill)) {
                    matchedSkills.push({
                        skill: niceSkill,
                        userScore: userSkill.score,
                        importance: 'nice-to-have',
                        userSkillName: userSkill.name
                    });
                    niceToHaveSet.delete(niceSkill.toLowerCase());
                    break;
                }
            }
        });

        const missingCriticalSkills = Array.from(requiredSkillsSet);
        const missingNiceToHave = Array.from(niceToHaveSet);
        const totalRequired = jobReqs.requiredSkills.length;
        const matchedRequired = matchedSkills.filter(s => s.importance === 'critical').length;
        const matchPercentage = totalRequired > 0 ? Math.round((matchedRequired / totalRequired) * 100) : 0;

        const recommendations = [];
        
        if (matchPercentage < 50) {
            recommendations.push(`⚠️ CRITICAL: You are significantly underqualified (${matchPercentage}% match)`);
        } else if (matchPercentage < 70) {
            recommendations.push(`⚠️ WARNING: You have significant skill gaps (${matchPercentage}% match)`);
        }

        if (missingCriticalSkills.length > 0) {
            recommendations.push(`❌ MISSING: ${missingCriticalSkills.slice(0, 5).join(', ')}`);
            recommendations.push(`Focus on learning these ${missingCriticalSkills.length} critical skills immediately`);
        }

        if (matchPercentage >= 70) {
            recommendations.push('✅ You have strong alignment with this role. Consider applying!');
        } else if (matchPercentage >= 50) {
            recommendations.push('⚠️ You need to address skill gaps before applying');
        } else {
            recommendations.push('❌ NOT RECOMMENDED: This role requires significant upskilling');
        }

        const comparison = {
            matchedSkills: matchedSkills,
            missingCriticalSkills: missingCriticalSkills,
            missingNiceToHave: missingNiceToHave,
            overqualifiedSkills: [],
            matchPercentage: matchPercentage,
            experienceGap: `This ${jobReqs.experienceLevel}-level role typically requires ${jobReqs.typicalYearsRequired} years of experience.`,
            recommendations: recommendations,
            strengthAreas: matchedSkills.filter(s => s.userScore >= 7).map(s => s.skill).slice(0, 5),
            weaknessAreas: missingCriticalSkills.slice(0, 5),
            detailedFeedback: {
                experienceGaps: [],
                skillGaps: [`Missing ${missingCriticalSkills.length} critical skills`],
                readinessAssessment: matchPercentage >= 70 ? 'READY' : matchPercentage >= 50 ? 'NEEDS IMPROVEMENT' : 'NOT READY',
                strengthAreas: matchedSkills.filter(s => s.userScore >= 7).map(s => s.skill),
                weeknessAreas: missingCriticalSkills
            }
        };
        
        return {
            jobRequirements: jobReqs,
            skillComparison: comparison,
            jobTitle: jobTitle,
            deepAnalysis: false
        };

    } catch (error) {
        console.error('Error comparing skills with job:', error);
        return { error: error.message };
    }
}

// IMPROVED: Calculate career readiness with detailed reasoning
function calculateCareerReadiness(userSkills, industryYears, educationYears, jobComparison) {
    const totalSkills = userSkills.length || 1;
    const strongSkills = userSkills.filter(s => s.score >= 7).length;
    const avgScore = userSkills.reduce((acc, s) => acc + s.score, 0) / totalSkills;

    let readinessScore = 0;
    const reasons = [];

    // Factor 1: Skill match (50% - most important)
    if (jobComparison && jobComparison.skillComparison) {
        const matchPercentage = jobComparison.skillComparison.matchPercentage || 0;
        const skillPoints = (matchPercentage / 100) * 50;
        readinessScore += skillPoints;
        
        if (matchPercentage < 50) {
            reasons.push(`❌ CRITICAL SKILL GAP: Only ${matchPercentage}% skill match (-${Math.round(50 - skillPoints)} points)`);
        } else if (matchPercentage < 70) {
            reasons.push(`⚠️ SKILL GAPS: ${matchPercentage}% skill match (-${Math.round(50 - skillPoints)} points)`);
        } else {
            reasons.push(`✅ Strong skill match: ${matchPercentage}% (+${Math.round(skillPoints)} points)`);
        }
    } else {
        const skillPoints = (avgScore / 10) * 50;
        readinessScore += skillPoints;
        reasons.push(`Average skill level: ${avgScore.toFixed(1)}/10 (+${Math.round(skillPoints)} points)`);
    }

    // Factor 2: Experience alignment (30%)
    if (jobComparison && jobComparison.jobRequirements) {
        const requiredYears = jobComparison.jobRequirements.typicalYearsRequired || 0;
        const experienceLevel = jobComparison.jobRequirements.experienceLevel;
        
        if (requiredYears === 0) {
            readinessScore += 30;
            reasons.push(`✅ Entry level role (+30 points)`);
        } else {
            const experienceRatio = industryYears / requiredYears;
            const experiencePoints = Math.min(experienceRatio * 30, 30);
            readinessScore += experiencePoints;
            
            if (industryYears === 0) {
                reasons.push(`❌ NO PROFESSIONAL EXPERIENCE: ${experienceLevel} role requires ${requiredYears}+ years (-30 points)`);
            } else if (experienceRatio < 0.5) {
                reasons.push(`❌ INSUFFICIENT EXPERIENCE: ${industryYears} years vs ${requiredYears} required (-${Math.round(30 - experiencePoints)} points)`);
            } else if (experienceRatio < 1) {
                reasons.push(`⚠️ BELOW EXPERIENCE REQUIREMENT: ${industryYears} years vs ${requiredYears} required (-${Math.round(30 - experiencePoints)} points)`);
            } else {
                reasons.push(`✅ Meets experience requirement: ${industryYears} years (+${Math.round(experiencePoints)} points)`);
            }
        }
    } else {
        const experienceScore = Math.min(industryYears * 5, 30);
        readinessScore += experienceScore;
        
        if (industryYears === 0) {
            reasons.push(`❌ No professional experience (0 points)`);
        } else if (industryYears < 2) {
            reasons.push(`⚠️ Limited experience: ${industryYears} year(s) (+${Math.round(experienceScore)} points)`);
        } else {
            reasons.push(`✅ ${industryYears} years experience (+${Math.round(experienceScore)} points)`);
        }
    }

    // Factor 3: Skill strength/quality (15%)
    const qualityScore = (strongSkills / totalSkills) * 15;
    readinessScore += qualityScore;
    
    const strongPercent = Math.round((strongSkills / totalSkills) * 100);
    if (strongPercent < 30) {
        reasons.push(`❌ WEAK SKILL PROFICIENCY: Only ${strongPercent}% of skills are strong (-${Math.round(15 - qualityScore)} points)`);
    } else if (strongPercent < 50) {
        reasons.push(`⚠️ Low skill proficiency: ${strongPercent}% strong skills (+${Math.round(qualityScore)} points)`);
    } else {
        reasons.push(`✅ ${strongPercent}% of skills are strong (+${Math.round(qualityScore)} points)`);
    }

    // Factor 4: Education foundation (5%)
    const educationScore = Math.min(educationYears * 1.25, 5);
    readinessScore += educationScore;
    
    if (educationYears === 0) {
        reasons.push(`⚠️ No formal education listed (0 points)`);
    } else if (educationYears < 4) {
        reasons.push(`⚠️ ${educationYears} years education (+${Math.round(educationScore)} points)`);
    } else {
        reasons.push(`✅ ${educationYears} years education (+${Math.round(educationScore)} points)`);
    }

    const finalScore = Math.round(Math.min(readinessScore, 100));

    return {
        score: finalScore,
        reasons: reasons,
        verdict: finalScore >= 70 ? 'READY TO APPLY' : finalScore >= 50 ? 'NEEDS IMPROVEMENT' : 'NOT READY - SIGNIFICANT GAPS'
    };
}

// IMPROVED: Calculate experience relevance with detailed reasoning
function calculateExperienceRelevance(industryYears, educationYears, userSkills, jobComparison) {
    let relevanceScore = 0;
    const reasons = [];

    // Factor 1: Years of industry experience (40%)
    const industryPoints = Math.min(industryYears * 8, 40);
    relevanceScore += industryPoints;
    
    if (industryYears === 0) {
        reasons.push(`❌ NO PROFESSIONAL EXPERIENCE: Employers expect work history (0/40 points)`);
        reasons.push(`⚠️ Consider internships, freelance projects, or entry-level positions`);
    } else if (industryYears < 2) {
        reasons.push(`⚠️ LIMITED EXPERIENCE: ${industryYears} year(s) professional work (+${Math.round(industryPoints)}/40 points)`);
        reasons.push(`💡 Gain more professional experience to improve relevance`);
    } else if (industryYears < 5) {
        reasons.push(`✅ Moderate experience: ${industryYears} years (+${Math.round(industryPoints)}/40 points)`);
    } else {
        reasons.push(`✅ Strong experience: ${industryYears} years (+${Math.round(industryPoints)}/40 points)`);
    }

    // Factor 2: Skill quality and demonstration (35%)
    const totalSkills = userSkills.length || 1;
    const demonstratedSkills = userSkills.filter(s => s.supported && s.score >= 6).length;
    const demonstratedPercentage = (demonstratedSkills / totalSkills) * 35;
    relevanceScore += demonstratedPercentage;
    
    const demoPercent = Math.round((demonstratedSkills / totalSkills) * 100);
    if (demoPercent < 30) {
        reasons.push(`❌ SKILLS NOT DEMONSTRATED: Only ${demoPercent}% of skills have evidence (-${Math.round(35 - demonstratedPercentage)} points)`);
        reasons.push(`⚠️ Build projects to demonstrate your claimed skills`);
    } else if (demoPercent < 60) {
        reasons.push(`⚠️ Limited skill demonstration: ${demoPercent}% verified (+${Math.round(demonstratedPercentage)}/35 points)`);
    } else {
        reasons.push(`✅ Well-demonstrated skills: ${demoPercent}% verified (+${Math.round(demonstratedPercentage)}/35 points)`);
    }

    // Factor 3: Job-specific skill match (20%)
    if (jobComparison && jobComparison.skillComparison) {
        const matchedCritical = jobComparison.skillComparison.matchedSkills?.filter(
            s => s.importance === 'critical' && s.userScore >= 6
        ).length || 0;
        const totalCritical = jobComparison.jobRequirements.requiredSkills?.length || 1;
        const criticalMatchPercentage = (matchedCritical / totalCritical) * 20;
        relevanceScore += criticalMatchPercentage;
        
        const criticalPercent = Math.round((matchedCritical / totalCritical) * 100);
        if (criticalPercent < 50) {
            reasons.push(`❌ MISSING KEY SKILLS: Only ${criticalPercent}% of required skills (-${Math.round(20 - criticalMatchPercentage)} points)`);
        } else if (criticalPercent < 80) {
            reasons.push(`⚠️ Partial skill match: ${criticalPercent}% of required skills (+${Math.round(criticalMatchPercentage)}/20 points)`);
        } else {
            reasons.push(`✅ Strong skill alignment: ${criticalPercent}% match (+${Math.round(criticalMatchPercentage)}/20 points)`);
        }
    } else {
        const educationPoints = Math.min(educationYears * 4, 20);
        relevanceScore += educationPoints;
        
        if (educationYears < 2) {
            reasons.push(`⚠️ Limited education: ${educationYears} years (+${Math.round(educationPoints)}/20 points)`);
        } else {
            reasons.push(`✅ Education: ${educationYears} years (+${Math.round(educationPoints)}/20 points)`);
        }
    }

    // Factor 4: Recency and progression bonus (5%)
    if (industryYears > 0) {
        const avgSkillScore = userSkills.reduce((acc, s) => acc + s.score, 0) / totalSkills;
        const progressionBonus = (avgSkillScore / 10) * 5;
        relevanceScore += progressionBonus;
        
        if (avgSkillScore < 5) {
            reasons.push(`⚠️ Low average skill level: ${avgSkillScore.toFixed(1)}/10 (+${Math.round(progressionBonus)}/5 points)`);
        } else {
            reasons.push(`✅ Skill progression: ${avgSkillScore.toFixed(1)}/10 average (+${Math.round(progressionBonus)}/5 points)`);
        }
    } else {
        reasons.push(`❌ No progression tracking without professional experience (0/5 points)`);
    }

    const finalScore = Math.round(Math.min(relevanceScore, 100));

    return {
        score: finalScore,
        reasons: reasons,
        verdict: finalScore >= 70 ? 'HIGHLY RELEVANT' : finalScore >= 50 ? 'MODERATELY RELEVANT' : 'LOW RELEVANCE - NEEDS IMPROVEMENT'
    };
}

module.exports = {
    getCommonJobTitles,
    analyzeJobRequirements,
    compareSkillsWithJob,
    calculateCareerReadiness,
    calculateExperienceRelevance,
    categorizeSkillRuleBased
};