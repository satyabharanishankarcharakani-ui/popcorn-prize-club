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

-- 3B. CAMPAIGN FINANCES TABLE (OFFERS PROFIT & LOSS ENGINE)
CREATE TABLE IF NOT EXISTS campaign_finances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id VARCHAR(64) UNIQUE NOT NULL,
    campaign_name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED')),
    start_date DATE,
    end_date DATE,
    attributed_sales NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    product_cost NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    packaging_cost NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    other_expenses NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    unit_reward_cost NUMERIC(12, 2) NOT NULL DEFAULT 0.50,
    is_estimate BOOLEAN NOT NULL DEFAULT true,
    notes TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(128)
);

CREATE INDEX IF NOT EXISTS idx_campaign_finances_campaign_id ON campaign_finances(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_finances_status ON campaign_finances(status);

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
-- Guarantees atomic row-level locking (SELECT ... FOR UPDATE) and state check.
CREATE OR REPLACE FUNCTION redeem_reward_atomic(
    p_code VARCHAR,
    p_operator_id UUID,
    p_operator_name VARCHAR,
    p_notes TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_reward rewards%ROWTYPE;
BEGIN
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
        {"name": "50% Off Any Bag", "icon": "🏷️", "desc": "Enjoy half off on your next visit."},
        {"name": "Free Topping Upgrade", "icon": "✨", "desc": "Add caramel or butter drizzle free."},
        {"name": "Buy 1 Get 1 Free", "icon": "🎉", "desc": "Bring a friend for a free treat."},
        {"name": "Bonus Mini Movie Pack", "icon": "🍿", "desc": "Complimentary snack pack."}
    ]'::jsonb
)
ON CONFLICT DO NOTHING;

-- 8. STRICT ROW LEVEL SECURITY (RLS) POLICIES
-- 7B. DEFAULT CAMPAIGN FINANCES SEED
INSERT INTO campaign_finances (
    campaign_id,
    campaign_name,
    status,
    start_date,
    end_date,
    attributed_sales,
    product_cost,
    packaging_cost,
    other_expenses,
    unit_reward_cost,
    is_estimate,
    notes
)
VALUES (
    'cmp-golden-ticket-2026',
    'Popcorn Paradise Golden Ticket',
    'ACTIVE',
    '2026-10-01',
    '2026-11-30',
    1240.00,
    310.00,
    75.00,
    45.00,
    0.60,
    true,
    'Estimated launch figures for inaugural lucky card insert batch'
)
ON CONFLICT (campaign_id) DO NOTHING;

-- 8. STRICT ROW LEVEL SECURITY (RLS) POLICIES
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE rewards ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_finances ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Service Role (Serverless API Functions) has full access
CREATE POLICY service_role_all_users ON users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_all_rewards ON rewards FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_all_campaigns ON campaigns FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_all_finances ON campaign_finances FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_all_audit ON audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Public / Anon Users: Strict Zero Access to Private Tables
REVOKE ALL ON users FROM anon, authenticated;
REVOKE ALL ON audit_logs FROM anon, authenticated;
REVOKE ALL ON rewards FROM anon, authenticated;
REVOKE ALL ON campaign_finances FROM anon, authenticated;

-- Anon can read active campaigns description
CREATE POLICY anon_read_active_campaigns ON campaigns FOR SELECT TO anon USING (status = 'ACTIVE');
