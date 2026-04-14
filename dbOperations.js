const { Pool } = require('pg');


const pool = new Pool({
    connectionString: process.env.DATABASE_URL || null,
    // strip sslmode from URL and set ssl manually so it isn't overridden
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
    host:     process.env.DATABASE_URL ? undefined : (process.env.DB_HOST     || 'localhost'),
    port:     process.env.DATABASE_URL ? undefined : (process.env.DB_PORT     || 5432),
    database: process.env.DATABASE_URL ? undefined : (process.env.DB_NAME     || 'cvision'),
    user:     process.env.DATABASE_URL ? undefined : (process.env.DB_USER     || 'postgres'),
    password: process.env.DATABASE_URL ? undefined : (process.env.DB_PASSWORD || ''),
});

module.exports = { pool };

/* 
   USER CV ANALYSIS OPERATIONS
   */

// Save CV analysis results to database
async function saveCVAnalysis(userId, analysisData) {
    try {
        const query = `
            INSERT INTO cv_analyses 
            (user_id, skills, education, experience, education_years, industry_years, 
             skills_by_type, summary, analyzed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            RETURNING id, analyzed_at
        `;

        const values = [
            userId,
            JSON.stringify(analysisData.skills),
            JSON.stringify(analysisData.education),
            JSON.stringify(analysisData.experience),
            analysisData.educationYears,
            analysisData.industryYears,
            JSON.stringify(analysisData.skillsByType),
            JSON.stringify(analysisData.summary)
        ];

        const result = await pool.query(query, values);
        return {
            success: true,
            analysisId: result.rows[0].id,
            analyzedAt: result.rows[0].analyzed_at
        };
    } catch (error) {
        console.error('Error saving CV analysis:', error);
        return { success: false, error: error.message };
    }
}

// Get user's most recent CV analysis
async function getLatestCVAnalysis(userId) {
    try {
        const query = `
            SELECT id, skills, education, experience, education_years, 
                   industry_years, skills_by_type, summary, analyzed_at
            FROM cv_analyses
            WHERE user_id = $1
            ORDER BY analyzed_at DESC
            LIMIT 1
        `;

        const result = await pool.query(query, [userId]);

        if (result.rows.length === 0) {
            return { success: false, hasAnalysis: false, message: 'No CV analysis found' };
        }

        const analysis = result.rows[0];
        return {
            success: true,
            hasAnalysis: true,
            data: {
                analysisId: analysis.id,
                skills: analysis.skills,
                education: analysis.education,
                experience: analysis.experience,
                educationYears: analysis.education_years,
                industryYears: analysis.industry_years,
                skillsByType: analysis.skills_by_type,
                summary: analysis.summary,
                analyzedAt: analysis.analyzed_at
            }
        };
    } catch (error) {
        console.error('Error fetching CV analysis:', error);
        return { success: false, error: error.message };
    }
}

// Get all CV analyses for a user
async function getAllCVAnalyses(userId) {
    try {
        const query = `
            SELECT id, analyzed_at, summary
            FROM cv_analyses
            WHERE user_id = $1
            ORDER BY analyzed_at DESC
        `;

        const result = await pool.query(query, [userId]);
        return {
            success: true,
            count: result.rows.length,
            analyses: result.rows.map(row => ({
                id: row.id,
                analyzedAt: row.analyzed_at,
                summary: row.summary
            }))
        };
    } catch (error) {
        console.error('Error fetching CV analyses:', error);
        return { success: false, error: error.message };
    }
}

// Get specific CV analysis by ID
async function getCVAnalysisById(userId, analysisId) {
    try {
        const query = `
            SELECT id, skills, education, experience, education_years, 
                   industry_years, skills_by_type, summary, analyzed_at
            FROM cv_analyses
            WHERE user_id = $1 AND id = $2
        `;

        const result = await pool.query(query, [userId, analysisId]);

        if (result.rows.length === 0) {
            return { success: false, message: 'Analysis not found' };
        }

        const analysis = result.rows[0];
        return {
            success: true,
            data: {
                analysisId: analysis.id,
                skills: analysis.skills,
                education: analysis.education,
                experience: analysis.experience,
                educationYears: analysis.education_years,
                industryYears: analysis.industry_years,
                skillsByType: analysis.skills_by_type,
                summary: analysis.summary,
                analyzedAt: analysis.analyzed_at
            }
        };
    } catch (error) {
        console.error('Error fetching CV analysis by ID:', error);
        return { success: false, error: error.message };
    }
}

// Delete CV analysis
async function deleteCVAnalysis(userId, analysisId) {
    try {
        const query = `DELETE FROM cv_analyses WHERE user_id = $1 AND id = $2 RETURNING id`;
        const result = await pool.query(query, [userId, analysisId]);

        if (result.rows.length === 0) {
            return { success: false, message: 'Analysis not found or already deleted' };
        }
        return { success: true, message: 'Analysis deleted successfully' };
    } catch (error) {
        console.error('Error deleting CV analysis:', error);
        return { success: false, error: error.message };
    }
}

// Save job comparison to database
async function saveJobComparison(userId, cvAnalysisId, jobComparisonData) {
    try {
        const query = `
            INSERT INTO job_comparisons 
            (user_id, cv_analysis_id, job_title, job_requirements, skill_comparison, 
             match_percentage, readiness_score, relevance_score, analyzed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            RETURNING id, analyzed_at
        `;

        const values = [
            userId,
            cvAnalysisId,
            jobComparisonData.jobTitle,
            JSON.stringify(jobComparisonData.jobRequirements),
            JSON.stringify(jobComparisonData.skillComparison),
            jobComparisonData.skillComparison.matchPercentage || 0,
            jobComparisonData.metrics.readinessScore,
            jobComparisonData.metrics.relevanceScore
        ];

        const result = await pool.query(query, values);
        return {
            success: true,
            comparisonId: result.rows[0].id,
            analyzedAt: result.rows[0].analyzed_at
        };
    } catch (error) {
        console.error('Error saving job comparison:', error);
        return { success: false, error: error.message };
    }
}

/* ================================
   RECRUITER/CANDIDATE OPERATIONS
   ================================ */

// Create new candidate
async function createCandidate(recruiterId, candidateData) {
    try {
        const query = `
            INSERT INTO candidates 
            (recruiter_id, name, email, phone, position_applied, cv_file_name, cv_text, status, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, uploaded_at
        `;

        const values = [
            recruiterId,
            candidateData.name,
            candidateData.email || null,
            candidateData.phone || null,
            candidateData.positionApplied,
            candidateData.cvFileName || null,
            candidateData.cvText,
            candidateData.status || 'pending',
            candidateData.notes || null
        ];

        const result = await pool.query(query, values);
        return {
            success: true,
            candidateId: result.rows[0].id,
            uploadedAt: result.rows[0].uploaded_at
        };
    } catch (error) {
        console.error('Error creating candidate:', error);
        return { success: false, error: error.message };
    }
}

// Save candidate analysis
async function saveCandidateAnalysis(candidateId, recruiterId, analysisData) {
    try {
        const query = `
            INSERT INTO candidate_analyses 
            (candidate_id, recruiter_id, job_title, skills, education, experience, 
             education_years, industry_years, skills_by_type, summary, job_comparison,
             match_percentage, experience_relevance_score, strengths, skill_gaps, 
             recommended_training, analyzed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
            RETURNING id, analyzed_at
        `;

        const values = [
            candidateId,
            recruiterId,
            analysisData.jobTitle,
            JSON.stringify(analysisData.skills),
            JSON.stringify(analysisData.education),
            JSON.stringify(analysisData.experience),
            analysisData.educationYears,
            analysisData.industryYears,
            JSON.stringify(analysisData.skillsByType),
            JSON.stringify(analysisData.summary),
            JSON.stringify(analysisData.jobComparison),
            analysisData.matchPercentage,
            analysisData.experienceRelevanceScore,
            analysisData.strengths,
            analysisData.skillGaps,
            analysisData.recommendedTraining
        ];

        const result = await pool.query(query, values);
        return {
            success: true,
            analysisId: result.rows[0].id,
            analyzedAt: result.rows[0].analyzed_at
        };
    } catch (error) {
        console.error('Error saving candidate analysis:', error);
        return { success: false, error: error.message };
    }
}

// Get all candidates for a recruiter
async function getAllCandidates(recruiterId, filters = {}) {
    try {
        let query = `
            SELECT c.id, c.name, c.email, c.phone, c.position_applied, c.status, 
                   c.uploaded_at, c.notes,
                   ca.match_percentage, ca.experience_relevance_score
            FROM candidates c
            LEFT JOIN candidate_analyses ca ON c.id = ca.candidate_id
            WHERE c.recruiter_id = $1
        `;

        const values = [recruiterId];
        let paramIndex = 2;

        // Add filters
        if (filters.status) {
            query += ` AND c.status = $${paramIndex}`;
            values.push(filters.status);
            paramIndex++;
        }

        if (filters.position) {
            query += ` AND c.position_applied ILIKE $${paramIndex}`;
            values.push(`%${filters.position}%`);
            paramIndex++;
        }

        query += ` ORDER BY c.uploaded_at DESC`;

        if (filters.limit) {
            query += ` LIMIT $${paramIndex}`;
            values.push(filters.limit);
        }

        const result = await pool.query(query, values);
        return {
            success: true,
            count: result.rows.length,
            candidates: result.rows
        };
    } catch (error) {
        console.error('Error fetching candidates:', error);
        return { success: false, error: error.message };
    }
}

// Get candidate by ID with full analysis
async function getCandidateById(candidateId, recruiterId) {
    try {
        const query = `
            SELECT c.*, ca.*
            FROM candidates c
            LEFT JOIN candidate_analyses ca ON c.id = ca.candidate_id
            WHERE c.id = $1 AND c.recruiter_id = $2
        `;

        const result = await pool.query(query, [candidateId, recruiterId]);

        if (result.rows.length === 0) {
            return { success: false, message: 'Candidate not found' };
        }

        return {
            success: true,
            candidate: result.rows[0]
        };
    } catch (error) {
        console.error('Error fetching candidate:', error);
        return { success: false, error: error.message };
    }
}

// Update candidate status
async function updateCandidateStatus(candidateId, recruiterId, status, notes = null) {
    try {
        const query = `
            UPDATE candidates 
            SET status = $1, notes = COALESCE($2, notes)
            WHERE id = $3 AND recruiter_id = $4
            RETURNING id, status
        `;

        const result = await pool.query(query, [status, notes, candidateId, recruiterId]);

        if (result.rows.length === 0) {
            return { success: false, message: 'Candidate not found' };
        }

        return {
            success: true,
            candidateId: result.rows[0].id,
            status: result.rows[0].status
        };
    } catch (error) {
        console.error('Error updating candidate status:', error);
        return { success: false, error: error.message };
    }
}

// Delete candidate
async function deleteCandidate(candidateId, recruiterId) {
    try {
        const query = `
            DELETE FROM candidates 
            WHERE id = $1 AND recruiter_id = $2
            RETURNING id
        `;

        const result = await pool.query(query, [candidateId, recruiterId]);

        if (result.rows.length === 0) {
            return { success: false, message: 'Candidate not found' };
        }

        return { success: true, message: 'Candidate deleted successfully' };
    } catch (error) {
        console.error('Error deleting candidate:', error);
        return { success: false, error: error.message };
    }
}

// Get candidate statistics for recruiter dashboard
async function getRecruiterStats(recruiterId) {
    try {
        const query = `
            SELECT 
                COUNT(*) as total_candidates,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
                COUNT(CASE WHEN status = 'shortlisted' THEN 1 END) as shortlisted,
                COUNT(CASE WHEN status = 'interviewing' THEN 1 END) as interviewing,
                COUNT(CASE WHEN status = 'hired' THEN 1 END) as hired,
                COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected,
                AVG(ca.match_percentage) as avg_match_percentage
            FROM candidates c
            LEFT JOIN candidate_analyses ca ON c.id = ca.candidate_id
            WHERE c.recruiter_id = $1
        `;

        const result = await pool.query(query, [recruiterId]);
        return {
            success: true,
            stats: result.rows[0]
        };
    } catch (error) {
        console.error('Error fetching recruiter stats:', error);
        return { success: false, error: error.message };
    }
}

module.exports = {
    // User operations
    saveCVAnalysis,
    getLatestCVAnalysis,
    getAllCVAnalyses,
    getCVAnalysisById,
    deleteCVAnalysis,
    saveJobComparison,
    
    // Recruiter operations
    createCandidate,
    saveCandidateAnalysis,
    getAllCandidates,
    getCandidateById,
    updateCandidateStatus,
    deleteCandidate,
    getRecruiterStats,
    
    pool
};