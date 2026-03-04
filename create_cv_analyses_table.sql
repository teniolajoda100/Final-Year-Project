-- Create cv_analyses table to store CV analysis results
CREATE TABLE IF NOT EXISTS cv_analyses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    skills JSONB NOT NULL,
    education JSONB,
    experience JSONB,
    education_years INTEGER DEFAULT 0,
    industry_years INTEGER DEFAULT 0,
    skills_by_type JSONB,
    summary JSONB,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create job_comparisons table to store job analysis results
CREATE TABLE IF NOT EXISTS job_comparisons (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cv_analysis_id INTEGER REFERENCES cv_analyses(id) ON DELETE CASCADE,
    job_title VARCHAR(255) NOT NULL,
    job_requirements JSONB,
    skill_comparison JSONB,
    match_percentage INTEGER,
    readiness_score INTEGER,
    relevance_score INTEGER,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create index on user_id for faster queries
CREATE INDEX idx_job_comparisons_user_id ON job_comparisons(user_id);

-- Create index on analyzed_at for faster sorting
CREATE INDEX idx_job_comparisons_analyzed_at ON job_comparisons(analyzed_at DESC);
-- Create index on user_id for faster queries
CREATE INDEX idx_cv_analyses_user_id ON cv_analyses(user_id);

-- Create index on analyzed_at for faster sorting
CREATE INDEX idx_cv_analyses_analyzed_at ON cv_analyses(analyzed_at DESC);