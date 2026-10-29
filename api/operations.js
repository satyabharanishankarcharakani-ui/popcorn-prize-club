// api/operations.js
// Server-Validated CRUD for Sales, Refunds, Expenses, Products, Inventory, Shops, Notifications & Settings
const { getSessionFromRequest, sanitizeString } = require('./_security');
const {
  listShops,
  createShop,
  listProducts,
  createProduct,
  updateProduct,
  recordInventoryMovement,
  listInventoryMovements,
  createSale,
  listSales,
  createRefund,
  listRefunds,
  createExpense,
  updateExpense,
  listExpenses,
  listNotifications,
  markNotificationRead,
  getBusinessSettings,
  updateBusinessSettings,
  addAuditLog,
} = require('./_db');

module.exports = async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const session = getSessionFromRequest(req);
  if (!session) {
    return res.status(401).json({ error: 'Authentication required to access business operations.' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }
  body = body || {};

  const action = req.query?.action || body.action;

  try {
    // 1. SHOPS
    if (action === 'list-shops') {
      const shops = await listShops();
      return res.status(200).json({ success: true, shops });
    }

    if (req.method === 'POST' && action === 'create-shop') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Owner or Admin role required to create shops.' });
      }
      const name = sanitizeString(body.name, 80);
      if (!name) return res.status(400).json({ error: 'Shop name is required.' });
      const shop = await createShop({
        code: sanitizeString(body.code, 24),
        name,
        location: sanitizeString(body.location || '', 160),
        phone: sanitizeString(body.phone || '', 32),
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'SHOP_CREATED',
        target_type: 'SHOP',
        target_id: shop.id,
        details: { name: shop.name, code: shop.code },
      });
      return res.status(201).json({ success: true, shop });
    }

    // 2. PRODUCTS & INVENTORY
    if (action === 'list-products') {
      const [products, movements] = await Promise.all([
        listProducts(),
        listInventoryMovements({ limit: 50 }),
      ]);
      return res.status(200).json({ success: true, products, movements });
    }

    if (req.method === 'POST' && action === 'create-product') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Owner or Admin role required to manage products.' });
      }
      const name = sanitizeString(body.name, 80);
      if (!name) return res.status(400).json({ error: 'Product name is required.' });
      const product = await createProduct({
        sku: sanitizeString(body.sku, 32),
        name,
        category: sanitizeString(body.category || 'Popcorn', 48),
        unit_price: body.unit_price,
        unit_cost: body.unit_cost,
        stock_qty: body.stock_qty,
        reorder_level: body.reorder_level,
        created_by: session.full_name,
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'PRODUCT_CREATED',
        target_type: 'PRODUCT',
        target_id: product.id,
        details: { sku: product.sku, name: product.name, stock_qty: product.stock_qty },
      });
      return res.status(201).json({ success: true, product });
    }

    if (req.method === 'POST' && action === 'update-product') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Owner or Admin role required to update products.' });
      }
      const product = await updateProduct(body.id, {
        name: body.name ? sanitizeString(body.name, 80) : undefined,
        category: body.category ? sanitizeString(body.category, 48) : undefined,
        unit_price: body.unit_price,
        unit_cost: body.unit_cost,
        reorder_level: body.reorder_level,
        is_active: body.is_active,
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'PRODUCT_UPDATED',
        target_type: 'PRODUCT',
        target_id: body.id,
      });
      return res.status(200).json({ success: true, product });
    }

    if (req.method === 'POST' && action === 'record-movement') {
      const movement = await recordInventoryMovement({
        product_id: body.product_id,
        shop_id: body.shop_id || null,
        movement_type: sanitizeString(body.movement_type || 'IN', 32).toUpperCase(),
        quantity: body.quantity,
        unit_cost: body.unit_cost,
        reference_id: sanitizeString(body.reference_id || '', 64),
        notes: sanitizeString(body.notes || '', 200),
        created_by: session.full_name,
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'INVENTORY_MOVEMENT',
        target_type: 'PRODUCT',
        target_id: body.product_id,
        details: { type: movement.movement_type, quantity: movement.quantity },
      });
      return res.status(201).json({ success: true, movement });
    }

    // 3. SALES & REFUNDS
    if (action === 'list-sales') {
      const [sales, refunds] = await Promise.all([
        listSales({
          startDate: req.query?.startDate || body.startDate,
          endDate: req.query?.endDate || body.endDate,
          shopId: req.query?.shopId || body.shopId,
          paymentMethod: req.query?.paymentMethod || body.paymentMethod,
        }),
        listRefunds({
          startDate: req.query?.startDate || body.startDate,
          endDate: req.query?.endDate || body.endDate,
          shopId: req.query?.shopId || body.shopId,
        }),
      ]);
      return res.status(200).json({ success: true, sales, refunds });
    }

    if (req.method === 'POST' && action === 'create-sale') {
      const sale = await createSale({
        sale_date: sanitizeString(body.sale_date || '', 16),
        shop_id: body.shop_id || null,
        shop_name: sanitizeString(body.shop_name || 'Main Counter', 80),
        items: Array.isArray(body.items) ? body.items : [],
        gross_amount: body.gross_amount,
        discount_amount: body.discount_amount,
        cogs_amount: body.cogs_amount,
        payment_method: sanitizeString(body.payment_method || 'CASH', 16).toUpperCase(),
        payment_reference: sanitizeString(body.payment_reference || '', 80),
        external_tx_id: body.external_tx_id ? sanitizeString(body.external_tx_id, 80) : null,
        source: body.source === 'IMPORTED' ? 'IMPORTED' : 'MANUAL',
        notes: sanitizeString(body.notes || '', 240),
        created_by: session.full_name,
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'SALE_RECORDED',
        target_type: 'SALE',
        target_id: sale.id,
        details: {
          sale_number: sale.sale_number,
          net_amount: sale.net_amount,
          payment_method: sale.payment_method,
          payment_reference: sale.payment_reference,
        },
      });
      return res.status(201).json({ success: true, sale });
    }

    if (req.method === 'POST' && action === 'import-sales') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Owner or Admin role required to import transactions.' });
      }
      const rows = Array.isArray(body.transactions) ? body.transactions : [];
      if (rows.length === 0) {
        return res.status(400).json({ error: 'No transaction rows provided for import.' });
      }
      const imported = [];
      const duplicates = [];
      for (const row of rows.slice(0, 100)) {
        try {
          const sale = await createSale({
            sale_date: sanitizeString(row.sale_date || '', 16),
            shop_name: sanitizeString(row.shop_name || 'Main Counter', 80),
            gross_amount: row.gross_amount || row.amount,
            discount_amount: row.discount_amount || 0,
            cogs_amount: row.cogs_amount || 0,
            payment_method: sanitizeString(row.payment_method || 'UPI', 16).toUpperCase(),
            payment_reference: sanitizeString(row.payment_reference || row.utr || '', 80),
            external_tx_id: sanitizeString(row.external_tx_id || row.utr || '', 80) || null,
            source: 'IMPORTED',
            notes: sanitizeString(row.notes || 'Imported settlement record', 200),
            created_by: session.full_name,
          });
          imported.push(sale);
        } catch (err) {
          if (err.code === 'DUPLICATE_TRANSACTION' || err.statusCode === 409) {
            duplicates.push({
              reference: row.payment_reference || row.utr || row.external_tx_id,
              reason: err.message,
            });
          } else {
            throw err;
          }
        }
      }
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'SALES_IMPORTED',
        details: { imported_count: imported.length, duplicate_skipped_count: duplicates.length },
      });
      return res.status(200).json({
        success: true,
        imported_count: imported.length,
        duplicate_count: duplicates.length,
        imported,
        duplicates,
      });
    }

    if (req.method === 'POST' && action === 'create-refund') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Owner or Admin role required to issue refunds.' });
      }
      const refund = await createRefund({
        sale_id: body.sale_id || null,
        shop_id: body.shop_id || null,
        shop_name: sanitizeString(body.shop_name || 'Main Counter', 80),
        refund_date: sanitizeString(body.refund_date || '', 16),
        refund_amount: body.refund_amount,
        cogs_reversed: body.cogs_reversed,
        restock_items: Boolean(body.restock_items),
        reason: sanitizeString(body.reason || '', 200),
        payment_reference: sanitizeString(body.payment_reference || '', 80),
        created_by: session.full_name,
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'REFUND_RECORDED',
        target_type: 'REFUND',
        target_id: refund.id,
        details: { refund_amount: refund.refund_amount, sale_id: refund.sale_id, reason: refund.reason },
      });
      return res.status(201).json({ success: true, refund });
    }

    // 4. EXPENSES
    if (action === 'list-expenses') {
      const expenses = await listExpenses({
        startDate: req.query?.startDate || body.startDate,
        endDate: req.query?.endDate || body.endDate,
        shopId: req.query?.shopId || body.shopId,
        category: req.query?.category || body.category,
      });
      return res.status(200).json({ success: true, expenses });
    }

    if (req.method === 'POST' && action === 'create-expense') {
      const expense = await createExpense({
        expense_date: sanitizeString(body.expense_date || '', 16),
        shop_id: body.shop_id || null,
        shop_name: sanitizeString(body.shop_name || 'Main Counter', 80),
        category: sanitizeString(body.category || '', 64),
        amount: body.amount,
        vendor: sanitizeString(body.vendor || '', 80),
        payment_method: sanitizeString(body.payment_method || 'CASH', 16),
        reference: sanitizeString(body.reference || '', 80),
        receipt_url: sanitizeString(body.receipt_url || '', 240),
        notes: sanitizeString(body.notes || '', 240),
        source: body.source === 'IMPORTED' ? 'IMPORTED' : 'MANUAL',
        created_by: session.full_name,
      });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'EXPENSE_RECORDED',
        target_type: 'EXPENSE',
        target_id: expense.id,
        details: { category: expense.category, amount: expense.amount },
      });
      return res.status(201).json({ success: true, expense });
    }

    if (req.method === 'POST' && action === 'update-expense') {
      if (session.role !== 'OWNER' && session.role !== 'ADMIN') {
        return res.status(403).json({ error: 'Owner or Admin role required to edit expenses.' });
      }
      const updated = await updateExpense(body.id, {
        expense_date: body.expense_date ? sanitizeString(body.expense_date, 16) : undefined,
        category: body.category ? sanitizeString(body.category, 64) : undefined,
        amount: body.amount,
        vendor: body.vendor !== undefined ? sanitizeString(body.vendor, 80) : undefined,
        payment_method: body.payment_method ? sanitizeString(body.payment_method, 16) : undefined,
        reference: body.reference !== undefined ? sanitizeString(body.reference, 80) : undefined,
        notes: body.notes !== undefined ? sanitizeString(body.notes, 240) : undefined,
      });
      if (!updated) return res.status(404).json({ error: 'Expense record not found.' });
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'EXPENSE_UPDATED',
        target_type: 'EXPENSE',
        target_id: body.id,
      });
      return res.status(200).json({ success: true, expense: updated });
    }

    // 5. NOTIFICATIONS
    if (action === 'list-notifications') {
      const notifications = await listNotifications();
      return res.status(200).json({ success: true, notifications });
    }

    if (req.method === 'POST' && action === 'mark-notification-read') {
      await markNotificationRead(body.id);
      return res.status(200).json({ success: true });
    }

    // 6. BUSINESS SETTINGS
    if (action === 'get-settings') {
      const [settings, shops] = await Promise.all([getBusinessSettings(), listShops()]);
      return res.status(200).json({ success: true, settings, shops });
    }

    if (req.method === 'POST' && action === 'update-settings') {
      if (session.role !== 'OWNER') {
        return res.status(403).json({ error: 'Only the Primary Owner can modify business settings.' });
      }
      const settings = await updateBusinessSettings(
        {
          business_name: sanitizeString(body.business_name || 'LR Popcorn Prize Club', 80),
          currency: sanitizeString(body.currency || 'INR', 8),
          currency_symbol: sanitizeString(body.currency_symbol || '₹', 4),
          support_phone: sanitizeString(body.support_phone || '', 32),
          default_shop_name: sanitizeString(body.default_shop_name || 'Main Counter', 80),
        },
        session.full_name
      );
      await addAuditLog({
        actor_id: session.id,
        actor_name: session.full_name,
        actor_role: session.role,
        action: 'SETTINGS_UPDATED',
        target_type: 'SETTINGS',
        target_id: 'general',
      });
      return res.status(200).json({ success: true, settings });
    }

    return res.status(400).json({ error: 'Invalid operations action.' });
  } catch (err) {
    console.error('Operations endpoint error:', err.message);
    const status = err.statusCode || (err.message?.includes('CRITICAL CONFIGURATION ERROR') ? 503 : 500);
    return res.status(status).json({
      error: err.message || 'Failed to process operation.',
      code: err.code || (status === 503 ? 'DB_SETUP_REQUIRED' : 'OPERATION_ERROR'),
    });
  }
};
