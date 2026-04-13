const express = require('express');
const router = express.Router();
const multer = require('multer');
const mammoth = require('mammoth');
const fs = require('fs');

const { extractPDFText } = require('./cvAnalysis');
const { analyzeCandidateCV, compareCandidates } = require('./recruiteranalysis');
const {
    createCandidate,
    saveCandidateAnalysis,
    getAllCandidates,
    getCandidateById,
    updateCandidateStatus,
    deleteCandidate,
    getRecruiterStats
} = require('./dbOperations');

const upload = multer({ dest: 'uploads/' });

/* ================================
   MIDDLEWARE
   ================================ */

// Ensure user is a recruiter
function ensureRecruiter(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not logged in' });
    }
    if (req.session.role !== 'recruiter') {
        return res.status(403).json({ error: 'Access denied - Recruiter access only' });
    }
    next();
}

/* ================================
   RECRUITER DASHBOARD STATS
   ================================ */

router.get('/stats', ensureRecruiter, async (req, res) => {
    try {
        const stats = await getRecruiterStats(req.session.userId);
        res.json(stats);
    } catch (error) {
        console.error('Error fetching recruiter stats:', error);
        res.json({ error: error.message });
    }
});

/* ================================
   CANDIDATE MANAGEMENT
   ================================ */

// Get all candidates
router.get('/candidates', ensureRecruiter, async (req, res) => {
    try {
        const filters = {
            status: req.query.status,
            position: req.query.position,
            limit: req.query.limit ? parseInt(req.query.limit) : null
        };

        const result = await getAllCandidates(req.session.userId, filters);
        res.json(result);
    } catch (error) {
        console.error('Error fetching candidates:', error);
        res.json({ error: error.message });
    }
});

// Get single candidate with full analysis
router.get('/candidates/:id', ensureRecruiter, async (req, res) => {
    try {
        const result = await getCandidateById(
            parseInt(req.params.id),
            req.session.userId
        );
        res.json(result);
    } catch (error) {
        console.error('Error fetching candidate:', error);
        res.json({ error: error.message });
    }
});

// Upload and analyze candidate CV
router.post('/candidates/upload', ensureRecruiter, upload.single('cvFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.json({ error: 'No file uploaded' });
        }

        const { candidateName, jobTitle, email, phone } = req.body;

        if (!candidateName || !jobTitle) {
            fs.unlinkSync(req.file.path);
            return res.json({ error: 'Candidate name and job title are required' });
        }

        // Extract CV text
        let cvText = req.file.originalname.toLowerCase().endsWith('.pdf')
            ? await extractPDFText(req.file.path)
            : (await mammoth.extractRawText({ path: req.file.path })).value;

        fs.unlinkSync(req.file.path);

        if (!cvText || cvText.length < 100) {
            return res.json({ error: 'Could not extract sufficient text from CV' });
        }

        // Create candidate record
        const candidateData = {
            name: candidateName,
            email: email || null,
            phone: phone || null,
            positionApplied: jobTitle,
            cvFileName: req.file.originalname,
            cvText: cvText,
            status: 'pending'
        };

        const candidateResult = await createCandidate(req.session.userId, candidateData);
        
        if (!candidateResult.success) {
            return res.json({ error: 'Failed to create candidate record' });
        }

        // Analyze CV
        console.log(`\n🚀 Starting analysis for candidate: ${candidateName}`);
        const analysis = await analyzeCandidateCV(cvText, jobTitle, candidateName);

        // Save analysis
        const analysisData = {
            jobTitle: jobTitle,
            skills: analysis.skills,
            education: analysis.education,
            experience: analysis.experience,
            educationYears: analysis.educationYears,
            industryYears: analysis.industryYears,
            skillsByType: analysis.skillsByType,
            summary: analysis.summary,
            jobComparison: analysis.jobComparison,
            matchPercentage: analysis.matchPercentage,
            experienceRelevanceScore: analysis.experienceRelevanceScore,
            strengths: analysis.strengths,
            skillGaps: analysis.skillGaps,
            recommendedTraining: analysis.recommendedTraining
        };

        const analysisResult = await saveCandidateAnalysis(
            candidateResult.candidateId,
            req.session.userId,
            analysisData
        );

        if (!analysisResult.success) {
            console.error('Failed to save analysis, but candidate was created');
        }

        res.json({
            success: true,
            candidateId: candidateResult.candidateId,
            analysis: analysis,
            message: 'Candidate CV analyzed successfully'
        });

    } catch (error) {
        console.error('Error uploading candidate CV:', error);
        
        // Clean up file if it exists
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.json({ error: error.message });
    }
});

// Update candidate status
router.patch('/candidates/:id/status', ensureRecruiter, async (req, res) => {
    try {
        const { status, notes } = req.body;

        if (!status) {
            return res.json({ error: 'Status is required' });
        }

        const validStatuses = ['pending', 'shortlisted', 'interviewing', 'hired', 'rejected'];
        if (!validStatuses.includes(status)) {
            return res.json({ error: 'Invalid status' });
        }

        const result = await updateCandidateStatus(
            parseInt(req.params.id),
            req.session.userId,
            status,
            notes
        );

        res.json(result);
    } catch (error) {
        console.error('Error updating candidate status:', error);
        res.json({ error: error.message });
    }
});

// Delete candidate
router.delete('/candidates/:id', ensureRecruiter, async (req, res) => {
    try {
        const result = await deleteCandidate(
            parseInt(req.params.id),
            req.session.userId
        );
        res.json(result);
    } catch (error) {
        console.error('Error deleting candidate:', error);
        res.json({ error: error.message });
    }
});

/* ================================
   CANDIDATE COMPARISON
   ================================ */

// Compare multiple candidates for same position
router.post('/candidates/compare', ensureRecruiter, async (req, res) => {
    try {
        const { candidateIds } = req.body;

        if (!candidateIds || !Array.isArray(candidateIds) || candidateIds.length < 2) {
            return res.json({ error: 'At least 2 candidate IDs required for comparison' });
        }

        // Fetch all candidates
        const candidates = [];
        for (const id of candidateIds) {
            const result = await getCandidateById(id, req.session.userId);
            if (result.success) {
                candidates.push(result.candidate);
            }
        }

        if (candidates.length < 2) {
            return res.json({ error: 'Could not fetch enough candidates for comparison' });
        }

        // Build analysis objects
        const analyses = candidates.map(c => ({
            candidateId: c.id,
            name: c.name,
            matchPercentage: c.match_percentage,
            experienceRelevanceScore: c.experience_relevance_score,
            competitivenessScore: Math.round((c.match_percentage + c.experience_relevance_score) / 2 / 10),
            skills: c.skills,
            strengths: c.strengths,
            skillGaps: c.skill_gaps
        }));

        const ranked = compareCandidates(analyses);

        res.json({
            success: true,
            candidates: ranked,
            topCandidate: ranked[0]
        });

    } catch (error) {
        console.error('Error comparing candidates:', error);
        res.json({ error: error.message });
    }
});

module.exports = router;