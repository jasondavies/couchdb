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
  var db = new CouchDB("test_suite_db");
  db.deleteDb();
  db.createDb();

  var historyDoc = {_id: "historyDoc"};

  var testFun = function() {
    // Test that compaction doesn't normally remove old revs
    T(db.save(historyDoc).ok);
    var firstRev = historyDoc._rev;
    T(db.save(historyDoc).ok);
    var secondRev = historyDoc._rev;
    T(db.save(historyDoc).ok);
    // Forget the second rev
    historyDoc._rev = secondRev;
    T(db.deleteDoc(historyDoc, true).ok);
    T(db.compact().ok);
    T(db.last_req.status == 202);
    // compaction isn't instantaneous, loop until done
    while (db.info().compact_running) {};
    T(db.open(historyDoc._id, {rev: firstRev})._rev == firstRev);
    T(db.open(historyDoc._id, {rev: secondRev}) == null);
  }
  run_on_modified_server(
    [{section: "history",
      key: "test_suite_db", value: 'true'}],
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
