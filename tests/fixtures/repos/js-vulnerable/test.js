// Ananke test fixture: one offline test, no test framework needed.
const assert = require("assert");
const _ = require("lodash");

assert.deepStrictEqual(_.chunk([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
assert.strictEqual(_.get({ a: { b: 42 } }, "a.b"), 42);
console.log("js-vulnerable: 1 test passed");
