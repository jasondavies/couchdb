// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Do some tests on history (preservation of old revisions).
couchTests.history = function(debug) {
  var db = new CouchDB("test_suite_db", {"X-Couch-Full-Commit":"false"});
  var dbB = new CouchDB("test_suite_db_b", {"X-Couch-Full-Commit":"false"});
  db.deleteDb();
  db.createDb();
  dbB.deleteDb();
  dbB.createDb();

  var historyDoc = {_id: "historyDoc"};
  var dbPair = {
    source:"test_suite_db",
    target:"test_suite_db_b"
  };

  var testFun = function() {
    // Set up some revs
    T(db.save(historyDoc).ok);
    var firstRev = historyDoc._rev;
    T(db.save(historyDoc).ok);
    var secondRev = historyDoc._rev;
    T(db.save(historyDoc).ok);
    // Forget the second rev
    historyDoc._rev = secondRev;
    T(db.deleteDoc(historyDoc, true).ok);

    // Replication with validation to prevent "forgotten" revs getting through.
    var A = dbPair.source;
    var B = dbPair.target;
    T(dbB.save({
      _id: '_design/forgetmenot',
      validate_doc_update: 'function (newDoc, oldDoc, userCtx) { if (newDoc._forget) { throw {unauthorized: "I cannot forget."}; } }'
    }).ok);
    var result = CouchDB.replicate(A, B);
    T(result.ok);
    T(result.history[0].doc_write_failures === 1);
    T(dbB.open(historyDoc._id, {rev: firstRev})._rev == firstRev);
    T(dbB.open(historyDoc._id, {rev: secondRev})._rev == secondRev);

    // Check that compaction removes the "forgotten" rev
    T(db.compact().ok);
    T(db.last_req.status == 202);
    // compaction isn't instantaneous, loop until done
    while (db.info().compact_running) {};
    T(db.open(historyDoc._id, {rev: firstRev})._rev == firstRev);
    T(db.open(historyDoc._id, {rev: secondRev}) == null);

    // Check that the "forgotten" rev doesn't get replicated
    dbB.deleteDb();
    dbB.createDb();
    var result = CouchDB.replicate(A, B);
    T(dbB.open(historyDoc._id, {rev: firstRev})._rev == firstRev);
    T(dbB.open(historyDoc._id, {rev: secondRev}) == null);
  }
  run_on_modified_server(
    [{section: "history",
      key: "test_suite_db", value: 'true'},
     {section: "history",
      key: "test_suite_db_b", value: 'true'}],
    testFun
  );

  // Run with history off

  // Test that compaction works twice on deleted docs
  T(db.compact().ok);
  T(db.last_req.status == 202);
  // compaction isn't instantaneous, loop until done
  while (db.info().compact_running) {};

  var oldRev = historyDoc._rev;
  T(db.save(historyDoc).ok);
  T(db.compact().ok);
  T(db.last_req.status == 202);
  // compaction isn't instantaneous, loop until done
  while (db.info().compact_running) {};
  T(db.open(historyDoc._id, {rev: oldRev}) == null)
};
