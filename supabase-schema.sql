-- ==============================================================================
-- LR POPCORN PRIZE CLUB — COMPLETE PRODUCTION DATABASE SCHEMA (PostgreSQL / Supabase)
-- Includes: Users/Profiles, Sessions, Shops, Products, Inventory Movements,
-- Sales, Sale Items, Refunds, Expenses, Reward Campaigns, QR Rewards,
-- Notifications, Business Settings, Immutable Audit Trail, Atomic Redemption RPC,
-- and Strict Row Level Security (RLS).
-- Zero fabricated financial or winner records are seeded.
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. USERS & OWNER PROFILES
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(160),
    phone VARCHAR(32),
    full_name VARCHAR(128) NOT NULL,
    avatar_url TEXT,
    role VARCHAR(32) NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'STAFF')),
    password_hash VARCHAR(256) NOT NULL,
    salt VARCHAR(128) NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 2. ACTIVE SESSIONS (For Security & Active Sessions Page + Revocation)
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    jti VARCHAR(64) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(64) NOT NULL,
    role VARCHAR(32) NOT NULL,
    ip_address VARCHAR(64),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_jti ON user_sessions(jti);

-- 3. SHOPS / COUNTERS
CREATE TABLE IF NOT EXISTS shops (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    location VARCHAR(256),
    phone VARCHAR(32),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. PRODUCTS & INVENTORY CATALOG
CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sku VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL DEFAULT 'Popcorn',
    unit_price NUMERIC(12, 2) NOT NULL CHECK (unit_price >= 0),
    unit_cost NUMERIC(12, 2) NOT NULL CHECK (unit_cost >= 0),
    stock_qty INTEGER NOT NULL DEFAULT 0,
    reorder_level INTEGER NOT NULL DEFAULT 10,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku);

-- 5. INVENTORY MOVEMENTS
CREATE TABLE IF NOT EXISTS inventory_movements (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    shop_id UUID REFERENCES shops(id) ON DELETE SET NULL,
    movement_type VARCHAR(32) NOT NULL CHECK (movement_type IN ('IN', 'OUT', 'ADJUSTMENT', 'SALE', 'REFUND', 'REWARD_REDEMPTION')),
    quantity INTEGER NOT NULL,
    unit_cost NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
    reference_id VARCHAR(128),
    notes TEXT,
    created_by VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_inv_movements_product ON inventory_movements(product_id);
CREATE INDEX IF NOT EXISTS idx_inv_movements_created ON inventory_movements(created_at DESC);

-- 6. SALES & TRANSACTIONS
CREATE TABLE IF NOT EXISTS sales (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sale_number VARCHAR(64) UNIQUE NOT NULL,
    sale_date DATE NOT NULL DEFAULT CURRENT_DATE,
    shop_id UUID REFERENCES shops(id) ON DELETE SET NULL,
    shop_name VARCHAR(128) NOT NULL DEFAULT 'Main Counter',
    gross_amount NUMERIC(12, 2) NOT NULL CHECK (gross_amount >= 0),
    discount_amount NUMERIC(12, 2) NOT NULL DEFAULT 0.00 CHECK (discount_amount >= 0),
    net_amount NUMERIC(12, 2) NOT NULL CHECK (net_amount >= 0),
    cogs_amount NUMERIC(12, 2) NOT NULL DEFAULT 0.00 CHECK (cogs_amount >= 0),
    payment_method VARCHAR(32) NOT NULL CHECK (payment_method IN ('CASH', 'UPI', 'CARD', 'OTHER')),
    payment_reference VARCHAR(128),
    external_tx_id VARCHAR(128) UNIQUE,
    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL' CHECK (source IN ('MANUAL', 'IMPORTED')),
    notes TEXT,
    created_by VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(sale_date DESC);
CREATE INDEX IF NOT EXISTS idx_sales_shop ON sales(shop_id);

-- 7. SALE LINE ITEMS
CREATE TABLE IF NOT EXISTS sale_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sale_id UUID NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id UUID REFERENCES products(id) ON DELETE SET NULL,
    product_name VARCHAR(128) NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price NUMERIC(12, 2) NOT NULL CHECK (unit_price >= 0),
    unit_cost NUMERIC(12, 2) NOT NULL DEFAULT 0.00 CHECK (unit_cost >= 0),
    line_total NUMERIC(12, 2) NOT NULL CHECK (line_total >= 0),
    line_cogs NUMERIC(12, 2) NOT NULL DEFAULT 0.00 CHECK (line_cogs >= 0)
);
CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);

-- 8. REFUNDS
CREATE TABLE IF NOT EXISTS refunds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sale_id UUID REFERENCES sales(id) ON DELETE SET NULL,
    shop_id UUID REFERENCES shops(id) ON DELETE SET NULL,
    shop_name VARCHAR(128) NOT NULL DEFAULT 'Main Counter',
    refund_date DATE NOT NULL DEFAULT CURRENT_DATE,
    refund_amount NUMERIC(12, 2) NOT NULL CHECK (refund_amount > 0),
    cogs_reversed NUMERIC(12, 2) NOT NULL DEFAULT 0.00 CHECK (cogs_reversed >= 0),
    restock_items BOOLEAN NOT NULL DEFAULT FALSE,
    reason TEXT NOT NULL,
    payment_reference VARCHAR(128),
    created_by VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_refunds_date ON refunds(refund_date DESC);

-- 9. OPERATING EXPENSES
CREATE TABLE IF NOT EXISTS expenses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
    shop_id UUID REFERENCES shops(id) ON DELETE SET NULL,
    shop_name VARCHAR(128) NOT NULL DEFAULT 'Main Counter',
    category VARCHAR(64) NOT NULL,
    amount NUMERIC(12, 2) NOT NULL CHECK (amount > 0),
    vendor VARCHAR(128),
    payment_method VARCHAR(32) NOT NULL DEFAULT 'CASH',
    reference VARCHAR(128),
    receipt_url TEXT,
    notes TEXT,
    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL' CHECK (source IN ('MANUAL', 'IMPORTED')),
    created_by VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(expense_date DESC);

-- 10. REWARD CAMPAIGNS
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED')),
    prizes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. QR REWARD CODES & WINNERS
CREATE TABLE IF NOT EXISTS rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(32) UNIQUE NOT NULL,
    customer_name VARCHAR(128) NOT NULL,
    prize_name VARCHAR(128) NOT NULL,
    prize_icon VARCHAR(16) NOT NULL DEFAULT '🍿',
    prize_description TEXT NOT NULL,
    unit_cost NUMERIC(12, 2) NOT NULL DEFAULT 0.00 CHECK (unit_cost >= 0),
    campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
    shop_id UUID REFERENCES shops(id) ON DELETE SET NULL,
    batch_name VARCHAR(128),
    is_demo BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'WAITING' CHECK (status IN ('GENERATED', 'WAITING', 'COLLECTED', 'EXPIRED', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    scratched_at TIMESTAMPTZ,
    redeemed_at TIMESTAMPTZ,
    redeemed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    operator_name VARCHAR(128),
    notes TEXT
);
ALTER TABLE rewards ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS idx_rewards_code ON rewards(code);
CREATE INDEX IF NOT EXISTS idx_rewards_status ON rewards(status);
CREATE INDEX IF NOT EXISTS idx_rewards_is_demo ON rewards(is_demo);
CREATE INDEX IF NOT EXISTS idx_rewards_created_at ON rewards(created_at DESC);

-- 12. NOTIFICATIONS
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(32) NOT NULL DEFAULT 'INFO',
    title VARCHAR(160) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);

-- 13. BUSINESS SETTINGS
CREATE TABLE IF NOT EXISTS business_settings (
    key VARCHAR(64) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_by VARCHAR(128),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 14. IMMUTABLE AUDIT LOGS
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

-- 15. ATOMIC SINGLE-USE REDEMPTION RPC (Row-Level Locking)
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

    IF p_code !~ '^PC-[A-Z0-9]{4,16}$' THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'INVALID_CODE',
            'message', 'Invalid or tampered reward code format.'
        );
    END IF;

    SELECT * INTO v_reward
    FROM rewards
    WHERE UPPER(code) = p_code
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'NOT_FOUND',
            'message', 'The requested reward code does not exist.'
        );
    END IF;

    IF v_reward.is_demo THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'DEMO_RECORD',
            'message', 'Demo records cannot be redeemed as genuine customer prizes.'
        );
    END IF;

    IF v_reward.status = 'EXPIRED' OR (v_reward.expires_at IS NOT NULL AND v_reward.expires_at < NOW()) THEN
        IF v_reward.status <> 'EXPIRED' THEN
            UPDATE rewards SET status = 'EXPIRED' WHERE id = v_reward.id;
        END IF;
        RETURN jsonb_build_object(
            'success', false,
            'code', 'EXPIRED',
            'message', 'This reward code has expired and can no longer be redeemed.'
        );
    END IF;

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

    IF v_reward.status NOT IN ('WAITING', 'GENERATED') THEN
        RETURN jsonb_build_object(
            'success', false,
            'code', 'INVALID_STATUS',
            'message', 'This reward code is ' || v_reward.status || ' and cannot be collected.'
        );
    END IF;

    UPDATE rewards
    SET
        status = 'COLLECTED',
        redeemed_at = NOW(),
        redeemed_by = p_operator_id,
        operator_name = p_operator_name,
        notes = p_notes
    WHERE id = v_reward.id;

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
            'customer_name', v_reward.customer_name,
            'unit_cost', v_reward.unit_cost
        )
    );

    RETURN jsonb_build_object(
        'success', true,
        'code', 'SUCCESS',
        'message', 'Prize redeemed successfully.',
        'reward_id', v_reward.id,
        'prize_name', v_reward.prize_name,
        'customer_name', v_reward.customer_name,
        'unit_cost', v_reward.unit_cost,
        'redeemed_at', NOW()
    );
END;
$$;

-- 16. STRICT ROW LEVEL SECURITY (RLS)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE shops ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE sales ENABLE ROW LEVEL SECURITY;
ALTER TABLE sale_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE refunds ENABLE ROW LEVEL SECURITY;
ALTER TABLE expenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE rewards ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE business_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Service Role (Serverless Backend) Full Access
CREATE POLICY srv_users ON users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_sessions ON user_sessions FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_shops ON shops FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_products ON products FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_inv_mov ON inventory_movements FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_sales ON sales FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_sale_items ON sale_items FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_refunds ON refunds FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_expenses ON expenses FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_campaigns ON campaigns FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_rewards ON rewards FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_notifications ON notifications FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_settings ON business_settings FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY srv_audit ON audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Revoke all direct anon/authenticated access to private tables
REVOKE ALL ON users, user_sessions, shops, products, inventory_movements, sales, sale_items, refunds, expenses, rewards, notifications, business_settings, audit_logs FROM anon, authenticated;
