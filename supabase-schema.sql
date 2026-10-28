-- ==============================================================================
-- LR POPCORN CLUB - PRODUCTION DATABASE SCHEMA & ATOMIC CONCURRENCY ENGINE
-- Database: PostgreSQL (Compatible with Supabase Free Tier)
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. USERS & ROLE-BASED ACCESS CONTROL
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(64) UNIQUE NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'STAFF')),
    password_hash VARCHAR(256) NOT NULL,
    salt VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

-- Index for authentication lookup
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 3. CAMPAIGNS TABLE
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(128) NOT NULL,
    description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED')),
    prizes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. REWARDS TABLE (LUCKY GIFT CARDS)
CREATE TABLE IF NOT EXISTS rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(32) UNIQUE NOT NULL,
    customer_name VARCHAR(128) NOT NULL,
    prize_name VARCHAR(128) NOT NULL,
    prize_icon VARCHAR(16) NOT NULL DEFAULT '🍿',
    prize_description TEXT NOT NULL,
    campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'WAITING' CHECK (status IN ('WAITING', 'COLLECTED', 'EXPIRED', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    redeemed_at TIMESTAMPTZ,
    redeemed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    operator_name VARCHAR(128),
    notes TEXT
);

-- Crucial unique index on reward code for high-performance lookup
CREATE UNIQUE INDEX IF NOT EXISTS idx_rewards_code ON rewards(code);
CREATE INDEX IF NOT EXISTS idx_rewards_status ON rewards(status);
CREATE INDEX IF NOT EXISTS idx_rewards_created_at ON rewards(created_at DESC);

-- 5. AUDIT LOGS TABLE (IMMUTABLE OPERATIONAL TRAIL)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id UUID,
    actor_name VARCHAR(128) NOT NULL,
    actor_role VARCHAR(32) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(64),
    target_id VARCHAR(128),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- 6. ATOMIC CONCURRENCY ENGINE: SINGLE-USE REDEMPTION STORED PROCEDURE
-- This procedure guarantees that two simultaneous requests for the same code CANNOT both succeed.
-- It acquires an exclusive row-level lock (FOR UPDATE) and only updates rows in 'WAITING' status.
CREATE OR REPLACE FUNCTION redeem_reward_atomic(
    p_code VARCHAR,
    p_operator_id UUID,
    p_operator_name VARCHAR,
    p_notes TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_reward rewards%ROWTYPE;
    v_result JSONB;
BEGIN
    -- Standardize input
    p_code := UPPER(TRIM(p_code));

    -- Acquire exclusive row lock
    SELECT * INTO v_reward
    FROM rewards
    WHERE UPPER(code) = p_code
    FOR UPDATE;

    -- Case 1: Code not found
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'NOT_FOUND',
            'message', 'The requested reward code does not exist in our system.'
        );
    END IF;

    -- Case 2: Code already collected / redeemed
    IF v_reward.status = 'COLLECTED' THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'ALREADY_REDEEMED',
            'message', 'This reward code was already redeemed.',
            'redeemed_at', v_reward.redeemed_at,
            'redeemed_by', v_reward.operator_name,
            'customer_name', v_reward.customer_name,
            'prize_name', v_reward.prize_name
        );
    END IF;

    -- Case 3: Code revoked or expired
    IF v_reward.status != 'WAITING' THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'INVALID_STATUS',
            'message', 'This reward code is ' || v_reward.status || ' and cannot be collected.'
        );
    END IF;

    -- Case 4: Eligible for atomic collection
    UPDATE rewards
    SET
        status = 'COLLECTED',
        redeemed_at = NOW(),
        redeemed_by = p_operator_id,
        operator_name = p_operator_name,
        notes = p_notes
    WHERE id = v_reward.id;

    -- Log audit entry
    INSERT INTO audit_logs (
        actor_id,
        actor_name,
        actor_role,
        action,
        target_type,
        target_id,
        details
    ) VALUES (
        p_operator_id,
        p_operator_name,
        'STAFF',
        'REWARD_REDEEMED',
        'REWARD',
        v_reward.id::text,
        jsonb_build_object(
            'code', p_code,
            'prize_name', v_reward.prize_name,
            'customer_name', v_reward.customer_name
        )
    );

    RETURN jsonb_build_object(
        'success', true,
        'code', 'SUCCESS',
        'message', 'Prize redeemed successfully.',
        'reward_id', v_reward.id,
        'prize_name', v_reward.prize_name,
        'customer_name', v_reward.customer_name,
        'redeemed_at', NOW()
    );
END;
$$;

-- 7. DEFAULT CAMPAIGN SEED
INSERT INTO campaigns (name, description, status, prizes)
VALUES (
    'Popcorn Paradise Golden Ticket',
    'Official QR gift reward campaign for store popcorn packs',
    'ACTIVE',
    '[
        {"name": "Free Popcorn Tub!", "icon": "🍿", "desc": "One fresh popcorn tub on the house."},
        {"name": "50% Off Any Bag", "icon": "🏷️", "desc": "Enjoy half off on your next purchase."},
        {"name": "Free Topping Upgrade", "icon": "✨", "desc": "Add caramel or butter drizzle free."},
        {"name": "Buy 1 Get 1 Free", "icon": "🎉", "desc": "Bring a friend for a free treat."},
        {"name": "Bonus Mini Movie Pack", "icon": "🍿", "desc": "Complimentary snack pack."}
    ]'::jsonb
)
ON CONFLICT DO NOTHING;

-- 8. ROW LEVEL SECURITY (RLS) POLICIES
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE rewards ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Server functions with service role bypass RLS, ensuring zero public data exposure.
-- Public anon cannot select or insert into users or audit_logs.
