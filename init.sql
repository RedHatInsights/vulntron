-- init.sql

-- Table to store deployment information
CREATE TABLE IF NOT EXISTS deployments (
    id SERIAL PRIMARY KEY,
    image_name VARCHAR(255) NOT NULL,
    deployment_date TIMESTAMP,
    component_name VARCHAR(255),
    syft_output JSONB,
    grype_output JSONB
);