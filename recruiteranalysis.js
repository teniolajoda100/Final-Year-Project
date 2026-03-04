const OpenAI = require('openai');
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const {
    calculateProficiency,
    detectCategory,
    extractEducationYears,
    extractIndustryYears
} = require('./cvAnalysis');

const {
    analyzeJobRequirements
} = require('./jobAnalysis');

/* ================================
   CANDIDATE CV ANALYSIS FOR RECRUITERS
   ================================ */

// Main function: Analyze candidate CV for specific job position
async function analyzeCandidateCV(cvText, jobTitle, candidateName = 'Candidate') {
    try {
        console.log(`\n🔍 Analyzing candidate: ${candidateName} for ${jobTitle}`);

        if (!cvText || cvText.length < 100) {
            throw new Error('CV text is too short or empty');
        }

        // Step 1: Extract basic info from CV
        console.log('📄 Step 1: Extracting candidate information...');
        const extractionResponse = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{
                role: 'user',
                content: `Extract CV data as JSON. Be thorough and extract ALL skills mentioned.

{
  "name": "Full Name",
  "email": "email@example.com",
  "phone": "+1234567890",
  "skills": ["skill1", "skill2", "skill3"],
  "education": ["University Name, Degree, 2020-2024"],
  "experience": ["Job Title at Company, 2023-Present", "Previous Job, 2021-2023"]
}

IMPORTANT: 
- Extract ALL skills, technologies, tools, and competencies mentioned
- Include years in YYYY-YYYY or YYYY-Present format
- Extract contact info if available

CV Text:
${cvText.substring(0, 4000)}`
            }],
            response_format: { type: 'json_object' },
            temperature: 0.3
        });

        const extractedData = JSON.parse(extractionResponse.choices[0].message.content);
        console.log(`   ✓ Found ${extractedData.skills?.length || 0} skills`);

        // Step 2: Calculate years of experience
        const educationYears = extractEducationYears(extractedData.education || []);
        const industryYears = extractIndustryYears(extractedData.experience || []);
        console.log(`   ✓ Experience: ${industryYears} years industry, ${educationYears} years education`);

        // Step 3: Get job requirements
        console.log('💼 Step 2: Analyzing job requirements...');
        const jobReqs = await analyzeJobRequirements(jobTitle);
        if (!jobReqs) {
            throw new Error('Could not analyze job requirements');
        }
        console.log(`   ✓ Job requires ${jobReqs.requiredSkills?.length || 0} critical skills`);

        // Step 4: Deep skill analysis with LLM
        console.log('🤖 Step 3: Performing deep skill analysis...');
        const skillAnalysisPrompt = `You are an expert technical recruiter analyzing a candidate for: "${jobTitle}"

JOB REQUIREMENTS:
Required Skills: ${JSON.stringify(jobReqs.requiredSkills)}
Nice-to-Have Skills: ${JSON.stringify(jobReqs.niceToHaveSkills)}
Experience Level: ${jobReqs.experienceLevel}
Years Required: ${jobReqs.typicalYearsRequired}

CANDIDATE PROFILE:
Skills Listed: ${JSON.stringify(extractedData.skills)}
Experience: ${industryYears} years industry, ${educationYears} years education
Education: ${JSON.stringify(extractedData.education)}
Work History: ${JSON.stringify(extractedData.experience)}

CV EXCERPT:
${cvText.substring(0, 3000)}

Analyze this candidate and respond with JSON:
{
  "skillsAnalysis": [
    {
      "skill": "JavaScript",
      "score": 8,
      "hasSkill": true,
      "evidence": "5+ years building React applications in production",
      "proficiencyLevel": "Advanced",
      "bloomLevel": "Apply"
    }
  ],
  "matchedRequiredSkills": ["JavaScript", "React", "Node.js"],
  "missingRequiredSkills": ["Docker", "Kubernetes"],
  "matchedNiceToHaveSkills": ["TypeScript", "AWS"],
  "missingNiceToHaveSkills": ["GraphQL"],
  "overallMatchPercentage": 75,
  "experienceMatch": "Meets requirements - ${industryYears} years vs ${jobReqs.typicalYearsRequired} required",
  "strengths": [
    "Strong frontend development skills with React ecosystem",
    "Proven leadership in technical projects",
    "Excellent problem-solving abilities demonstrated in CV"
  ],
  "weaknesses": [
    "Limited DevOps experience - no container orchestration",
    "Missing cloud infrastructure knowledge",
    "Backend skills need development"
  ],
  "detailedAssessment": "This candidate shows strong frontend capabilities with ${industryYears} years of experience. While they excel in React and JavaScript, they lack critical DevOps skills required for this role.",
  "hiringRecommendation": "SHORTLIST - Strong core skills but requires training in infrastructure",
  "recommendedInterviewFocus": [
    "Deep dive into React architecture decisions",
    "Assess willingness to learn DevOps practices",
    "Evaluate problem-solving approach with system design questions"
  ],
  "redFlags": ["No production deployment experience", "Job hopping - 3 jobs in 2 years"],
  "competitivenessScore": 7
}

Be thorough, honest, and actionable in your assessment.`;

        const skillAnalysisResponse = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: skillAnalysisPrompt }],
            response_format: { type: 'json_object' },
            temperature: 0.3,
            max_tokens: 2000
        });

        const analysis = JSON.parse(skillAnalysisResponse.choices[0].message.content);
        console.log(`   ✓ Match: ${analysis.overallMatchPercentage}%`);

        // Step 5: Calculate additional metrics
        const requiredSkillsCount = jobReqs.requiredSkills?.length || 1;
        const matchedRequiredCount = analysis.matchedRequiredSkills?.length || 0;
        const skillMatchPercentage = Math.round((matchedRequiredCount / requiredSkillsCount) * 100);

        // Experience relevance calculation
        const experienceRatio = industryYears / (jobReqs.typicalYearsRequired || 1);
        let experienceRelevance = 0;
        
        if (industryYears === 0) {
            experienceRelevance = 20; // Entry level
        } else if (experienceRatio >= 1) {
            experienceRelevance = 100; // Meets or exceeds
        } else if (experienceRatio >= 0.75) {
            experienceRelevance = 80; // Close enough
        } else if (experienceRatio >= 0.5) {
            experienceRelevance = 60; // Somewhat experienced
        } else {
            experienceRelevance = 40; // Under-experienced
        }

        // Adjust for match percentage
        experienceRelevance = Math.round((experienceRelevance + skillMatchPercentage) / 2);

        // Step 6: Build comprehensive skill gaps and training recommendations
        const skillGaps = analysis.missingRequiredSkills || [];
        const recommendedTraining = [];

        skillGaps.forEach(skill => {
            const skillLower = skill.toLowerCase();
            
            // Smart training recommendations based on skill type
            if (skillLower.includes('docker') || skillLower.includes('kubernetes')) {
                recommendedTraining.push(`Container Orchestration Fundamentals (Docker & Kubernetes)`);
            } else if (skillLower.includes('aws') || skillLower.includes('azure') || skillLower.includes('cloud')) {
                recommendedTraining.push(`Cloud Platform Certification (${skill})`);
            } else if (skillLower.includes('react') || skillLower.includes('angular') || skillLower.includes('vue')) {
                recommendedTraining.push(`${skill} Advanced Patterns & Best Practices`);
            } else if (skillLower.includes('python') || skillLower.includes('java') || skillLower.includes('javascript')) {
                recommendedTraining.push(`${skill} Programming - Intermediate to Advanced`);
            } else if (skillLower.includes('sql') || skillLower.includes('database')) {
                recommendedTraining.push(`Database Design & ${skill} Optimization`);
            } else {
                recommendedTraining.push(`${skill} Essentials & Best Practices`);
            }
        });

        // Add soft skill recommendations if needed
        if (industryYears < 2) {
            recommendedTraining.push('Professional Communication & Team Collaboration');
        }
        if (jobReqs.experienceLevel === 'Senior' && industryYears < 5) {
            recommendedTraining.push('Technical Leadership & Mentoring');
        }

        // Step 7: Categorize skills by type
        const technicalSkills = (analysis.skillsAnalysis || []).filter(s => {
            const tech = ['javascript', 'python', 'java', 'react', 'node', 'sql', 'aws', 'docker'];
            return tech.some(t => s.skill?.toLowerCase().includes(t));
        });

        const softSkills = (analysis.skillsAnalysis || []).filter(s => {
            const soft = ['communication', 'leadership', 'teamwork', 'problem solving'];
            return soft.some(t => s.skill?.toLowerCase().includes(t));
        });

        const skillsByType = {
            technical: technicalSkills.length,
            soft: softSkills.length,
            business: (analysis.skillsAnalysis?.length || 0) - technicalSkills.length - softSkills.length
        };

        // Step 8: Build final analysis result
        const result = {
            // Basic candidate info
            name: extractedData.name || candidateName,
            email: extractedData.email || null,
            phone: extractedData.phone || null,
            
            // Skills breakdown
            skills: analysis.skillsAnalysis || [],
            education: extractedData.education || [],
            experience: extractedData.experience || [],
            educationYears,
            industryYears,
            skillsByType,
            
            // Job matching
            jobTitle,
            jobComparison: {
                requiredSkills: jobReqs.requiredSkills || [],
                niceToHaveSkills: jobReqs.niceToHaveSkills || [],
                matchedRequired: analysis.matchedRequiredSkills || [],
                missingRequired: analysis.missingRequiredSkills || [],
                matchedNiceToHave: analysis.matchedNiceToHaveSkills || [],
                missingNiceToHave: analysis.missingNiceToHaveSkills || [],
                experienceRequired: jobReqs.typicalYearsRequired,
                experienceLevel: jobReqs.experienceLevel
            },
            
            // Scores & metrics
            matchPercentage: analysis.overallMatchPercentage || skillMatchPercentage,
            experienceRelevanceScore: experienceRelevance,
            competitivenessScore: analysis.competitivenessScore || Math.round((analysis.overallMatchPercentage + experienceRelevance) / 2),
            
            // Detailed feedback
            strengths: analysis.strengths || [],
            weaknesses: analysis.weaknesses || [],
            skillGaps: skillGaps,
            recommendedTraining: recommendedTraining,
            
            // Hiring recommendation
            detailedAssessment: analysis.detailedAssessment || 'Analysis complete',
            hiringRecommendation: analysis.hiringRecommendation || 'Under review',
            recommendedInterviewFocus: analysis.recommendedInterviewFocus || [],
            redFlags: analysis.redFlags || [],
            
            // Summary stats
            summary: {
                totalSkills: analysis.skillsAnalysis?.length || 0,
                strongSkills: analysis.skillsAnalysis?.filter(s => s.score >= 7).length || 0,
                matchedRequiredSkills: analysis.matchedRequiredSkills?.length || 0,
                totalRequiredSkills: jobReqs.requiredSkills?.length || 0,
                averageScore: (analysis.skillsAnalysis?.reduce((acc, s) => acc + s.score, 0) || 0) / (analysis.skillsAnalysis?.length || 1)
            }
        };

        console.log(`✅ Complete analysis generated for ${candidateName}`);
        console.log(`   Match: ${result.matchPercentage}% | Experience: ${result.experienceRelevanceScore}% | Competitiveness: ${result.competitivenessScore}/10`);
        
        return result;

    } catch (error) {
        console.error('❌ Error analyzing candidate CV:', error);
        throw error;
    }
}

/* ================================
   CANDIDATE COMPARISON & RANKING
   ================================ */

// Compare and rank multiple candidates for the same position
function compareCandidates(candidateAnalyses) {
    if (!candidateAnalyses || candidateAnalyses.length === 0) {
        return [];
    }

    // Calculate composite scores for ranking
    const scoredCandidates = candidateAnalyses.map(candidate => {
        const matchWeight = 0.5;
        const experienceWeight = 0.3;
        const competitivenessWeight = 0.2;

        const compositeScore = (
            (candidate.matchPercentage || 0) * matchWeight +
            (candidate.experienceRelevanceScore || 0) * experienceWeight +
            (candidate.competitivenessScore || 0) * 10 * competitivenessWeight
        );

        return {
            ...candidate,
            compositeScore: Math.round(compositeScore)
        };
    });

    // Sort by composite score, then by match percentage
    const ranked = scoredCandidates
        .sort((a, b) => {
            if (b.compositeScore !== a.compositeScore) {
                return b.compositeScore - a.compositeScore;
            }
            if (b.matchPercentage !== a.matchPercentage) {
                return b.matchPercentage - a.matchPercentage;
            }
            return b.experienceRelevanceScore - a.experienceRelevanceScore;
        })
        .map((candidate, index) => ({
            ...candidate,
            rank: index + 1,
            rankCategory: index === 0 ? 'Top Candidate' : 
                         index < 3 ? 'Strong Candidate' : 
                         index < 5 ? 'Good Candidate' : 'Consider'
        }));

    return ranked;
}

/* ================================
   BATCH ANALYSIS
   ================================ */

// Analyze multiple candidates in batch
async function batchAnalyzeCandidates(candidates, jobTitle) {
    const results = [];
    
    for (let i = 0; i < candidates.length; i++) {
        const candidate = candidates[i];
        console.log(`\n📊 Analyzing candidate ${i + 1}/${candidates.length}`);
        
        try {
            const analysis = await analyzeCandidateCV(
                candidate.cvText,
                jobTitle,
                candidate.name
            );
            
            results.push({
                candidateId: candidate.id,
                name: candidate.name,
                analysis: analysis,
                success: true
            });
        } catch (error) {
            console.error(`❌ Failed to analyze ${candidate.name}:`, error.message);
            results.push({
                candidateId: candidate.id,
                name: candidate.name,
                error: error.message,
                success: false
            });
        }
    }
    
    return results;
}

/* ================================
   SKILL GAP ANALYSIS
   ================================ */

// Analyze skill gaps across multiple candidates for a position
function analyzeTeamSkillGaps(candidateAnalyses, jobRequirements) {
    const allRequiredSkills = jobRequirements.requiredSkills || [];
    const skillCoverage = {};

    // Initialize coverage tracking
    allRequiredSkills.forEach(skill => {
        skillCoverage[skill] = {
            skill: skill,
            candidatesWithSkill: 0,
            candidateNames: [],
            coveragePercentage: 0
        };
    });

    // Count coverage
    candidateAnalyses.forEach(candidate => {
        const matchedSkills = candidate.jobComparison?.matchedRequired || [];
        matchedSkills.forEach(skill => {
            if (skillCoverage[skill]) {
                skillCoverage[skill].candidatesWithSkill++;
                skillCoverage[skill].candidateNames.push(candidate.name || 'Unknown');
            }
        });
    });

    // Calculate percentages
    const totalCandidates = candidateAnalyses.length;
    Object.keys(skillCoverage).forEach(skill => {
        skillCoverage[skill].coveragePercentage = Math.round(
            (skillCoverage[skill].candidatesWithSkill / totalCandidates) * 100
        );
    });

    // Find critical gaps (skills covered by <50% of candidates)
    const criticalGaps = Object.values(skillCoverage)
        .filter(s => s.coveragePercentage < 50)
        .sort((a, b) => a.coveragePercentage - b.coveragePercentage);

    return {
        skillCoverage: Object.values(skillCoverage),
        criticalGaps: criticalGaps,
        totalCandidates: totalCandidates
    };
}

module.exports = {
    analyzeCandidateCV,
    compareCandidates,
    batchAnalyzeCandidates,
    analyzeTeamSkillGaps
};