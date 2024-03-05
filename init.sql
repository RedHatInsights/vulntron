-- init.sql

-- Table to store deployment information
CREATE TABLE IF NOT EXISTS deployments (
    id SERIAL PRIMARY KEY,
    image_name VARCHAR(255) NOT NULL,
    deployment_date TIMESTAMP,
    scan_date TIMESTAMP,
    component_name VARCHAR(255),
    syft_output JSONB,
    grype_output JSONB
);

-- select d.id, d.image_name, d.deployment_date, d.scan_date, d.component_name from deployments d;
