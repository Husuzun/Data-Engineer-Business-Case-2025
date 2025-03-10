-- DBT model for validating OS matching quality
-- This model identifies potential issues in the OS matching process

-- Create a CTE for matched OS counts
WITH matched_os_counts AS (
    SELECT
        cve_id,
        COUNT(*) AS match_count
    FROM
        matched_os
    GROUP BY
        cve_id
),

-- Create a CTE for unmatched OS counts
unmatched_os_counts AS (
    SELECT
        cve_id,
        COUNT(*) AS unmatched_count
    FROM
        unmatched_os
    GROUP BY
        cve_id
),

-- Create a CTE for CVEs with potentially inconsistent OS matches
inconsistent_matches AS (
    SELECT
        cr.cve_id,
        mo.original_text,
        os.os_name,
        CASE
            -- Flag cases where we suspect false matches
            WHEN POSITION(LOWER(os.os_name) IN LOWER(cr.description)) = 0 AND
                 POSITION(LOWER(os.os_name) IN LOWER(COALESCE(cr.platforms, ''))) = 0 AND
                 POSITION(LOWER(os.os_name) IN LOWER(COALESCE(cr.product, ''))) = 0
            THEN TRUE
            ELSE FALSE
        END AS potential_false_match
    FROM
        cve_records cr
    JOIN
        matched_os mo ON cr.cve_id = mo.cve_id
    JOIN
        os_reference os ON mo.os_id = os.id
),

-- Create a CTE for match quality metrics
match_quality AS (
    SELECT
        cr.cve_id,
        moc.match_count,
        COALESCE(uoc.unmatched_count, 0) AS unmatched_count,
        CASE
            WHEN COALESCE(moc.match_count, 0) = 0 THEN 'NO_MATCHES'
            WHEN COALESCE(uoc.unmatched_count, 0) = 0 THEN 'ALL_MATCHED'
            WHEN COALESCE(moc.match_count, 0) > COALESCE(uoc.unmatched_count, 0) THEN 'MOSTLY_MATCHED'
            ELSE 'MOSTLY_UNMATCHED'
        END AS match_quality,
        CASE
            WHEN EXISTS (
                SELECT 1 FROM inconsistent_matches im 
                WHERE im.cve_id = cr.cve_id AND im.potential_false_match = TRUE
            ) THEN TRUE
            ELSE FALSE
        END AS has_potential_false_matches
    FROM
        cve_records cr
    LEFT JOIN
        matched_os_counts moc ON cr.cve_id = moc.cve_id
    LEFT JOIN
        unmatched_os_counts uoc ON cr.cve_id = uoc.cve_id
)

-- Final validation model
SELECT
    cve_id,
    match_count,
    unmatched_count,
    match_quality,
    has_potential_false_matches,
    CASE
        WHEN match_quality = 'NO_MATCHES' THEN 'HIGH'
        WHEN has_potential_false_matches THEN 'HIGH'
        WHEN match_quality = 'MOSTLY_UNMATCHED' THEN 'MEDIUM'
        WHEN match_quality = 'ALL_MATCHED' THEN 'LOW'
        ELSE 'MEDIUM'
    END AS validation_priority
FROM
    match_quality
ORDER BY
    CASE
        WHEN match_quality = 'NO_MATCHES' THEN 1
        WHEN has_potential_false_matches THEN 2
        WHEN match_quality = 'MOSTLY_UNMATCHED' THEN 3
        ELSE 4
    END,
    cve_id; 