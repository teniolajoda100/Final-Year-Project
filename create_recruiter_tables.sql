-- ============================================
-- RECRUITER SYSTEM DATABASE SCHEMA
-- ============================================

-- Candidates table
CREATE TABLE IF NOT EXISTS candidates (
    id SERIAL PRIMARY KEY,
    recruiter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    position_applied VARCHAR(255) NOT NULL,
    cv_file_name VARCHAR(255),
    cv_text TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    notes TEXT,
    uploaded_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Candidate CV analyses
CREATE TABLE IF NOT EXISTS candidate_analyses (
    id SERIAL PRIMARY KEY,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    recruiter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_title VARCHAR(255) NOT NULL,
    skills JSONB NOT NULL,
    education JSONB,
    experience JSONB,
    education_years INTEGER DEFAULT 0,
    industry_years INTEGER DEFAULT 0,
    skills_by_type JSONB,
    summary JSONB,
    job_comparison JSONB,
    match_percentage INTEGER,
    experience_relevance_score INTEGER,
    strengths TEXT[],
    skill_gaps TEXT[],
    recommended_training TEXT[],
    analyzed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_candidates_recruiter_id ON candidates(recruiter_id);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_candidates_position ON candidates(position_applied);
CREATE INDEX IF NOT EXISTS idx_candidate_analyses_candidate_id ON candidate_analyses(candidate_id);
CREATE INDEX IF NOT EXISTS idx_candidate_analyses_recruiter_id ON candidate_analyses(recruiter_id);
CREATE INDEX IF NOT EXISTS idx_candidate_analyses_match_percentage ON candidate_analyses(match_percentage DESC);

-- Status check constraint
ALTER TABLE candidates ADD CONSTRAINT check_status 
CHECK (status IN ('pending', 'shortlisted', 'rejected', 'hired', 'interviewing'));