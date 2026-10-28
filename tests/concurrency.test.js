// tests/concurrency.test.js
// Automated Atomic Concurrency & Single-Use Verification
const assert = require('assert');
const {
  createReward,
  getRewardByCode,
  redeemRewardAtomic,
  bootstrapOwnerIfEmpty,
} = require('../api/_db');

async function runConcurrencyTests() {
  console.log('--- RUNNING ATOMIC SINGLE-USE REDEMPTION TESTS ---');
  await bootstrapOwnerIfEmpty();

  // 1. Single-use sequential redemption
  {
    const reward = await createReward({
      customer_name: 'Test Customer',
      prize_name: 'Free Popcorn Tub!',
      prize_icon: '🍿',
      prize_description: 'Test gift description',
    });

    assert.ok(reward.code, 'Reward code must be created');
    assert.strictEqual(reward.status, 'WAITING', 'Initial status must be WAITING');

    // First redemption attempt by Operator Shankar
    const firstRedeem = await redeemRewardAtomic({
      code: reward.code,
      operator_id: 'usr-operator-1',
      operator_name: 'Shankar',
      notes: 'First checkout test',
    });

    assert.strictEqual(firstRedeem.success, true, 'First redemption must succeed');
    assert.strictEqual(firstRedeem.code, 'SUCCESS');

    // Verification in database
    const updatedReward = await getRewardByCode(reward.code);
    assert.strictEqual(updatedReward.status, 'COLLECTED', 'Status must be transitioned to COLLECTED');
    assert.ok(updatedReward.redeemed_at, 'Timestamp must be recorded');
    assert.strictEqual(updatedReward.operator_name, 'Shankar');

    // Second redemption attempt on the same code (must be rejected)
    const secondRedeem = await redeemRewardAtomic({
      code: reward.code,
      operator_id: 'usr-operator-2',
      operator_name: 'Staff Member',
    });

    assert.strictEqual(secondRedeem.success, false, 'Second redemption must fail');
    assert.strictEqual(secondRedeem.code, 'ALREADY_REDEEMED', 'Error code must be ALREADY_REDEEMED');

    console.log('✓ Sequential single-use redemption enforcement passed.');
  }

  // 2. Race condition & simultaneous concurrent redemptions
  {
    const raceReward = await createReward({
      customer_name: 'Race Winner',
      prize_name: '50% Off Any Bag',
      prize_icon: '🏷️',
    });

    // Fire 2 concurrent redemption requests simultaneously using Promise.all
    const [resultA, resultB] = await Promise.all([
      redeemRewardAtomic({
        code: raceReward.code,
        operator_id: 'usr-op-a',
        operator_name: 'Operator A',
      }),
      redeemRewardAtomic({
        code: raceReward.code,
        operator_id: 'usr-op-b',
        operator_name: 'Operator B',
      }),
    ]);

    const successes = [resultA, resultB].filter(r => r.success === true);
    const failures = [resultA, resultB].filter(r => r.success === false);

    assert.strictEqual(successes.length, 1, 'Exactly one concurrent redemption request must succeed');
    assert.strictEqual(failures.length, 1, 'The competing concurrent redemption request must fail');
    assert.ok(
      failures[0].code === 'ALREADY_REDEEMED' || failures[0].code === 'CONCURRENT_REQUEST',
      'Failing request must receive ALREADY_REDEEMED or CONCURRENT_REQUEST'
    );

    console.log('✓ Concurrency race condition prevention passed: zero duplicate redemptions allowed.');
  }

  console.log('ALL ATOMIC CONCURRENCY TESTS PASSED SUCCESSFULLY! ✓\n');
}

runConcurrencyTests().catch(err => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
