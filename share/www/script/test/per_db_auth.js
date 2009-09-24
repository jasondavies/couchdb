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

couchTests.per_db_auth = function(debug) {

  var db = new CouchDB("test_suite_db", {"X-Couch-Full-Commit":"false"});
  db.deleteDb();
  db.createDb();
  if (debug) debugger;

  run_on_modified_server(
    [{section: "httpd",
      key: "authentication_handlers",
      value: "{couch_httpd_auth, special_test_authentication_handler}"},
     {section:"httpd",
      key: "WWW-Authenticate",
      value:  "X-Couch-Test-Auth"}],

    function () {
      // Set up some users
      T(CouchDB.createUser("test_read", "testpassword", "test@somemail.com", ['read']).ok);
      T(CouchDB.createUser("test_write", "testpassword", "test@somemail.com", ['write']).ok);
      T(CouchDB.createUser("test_readwrite", "testpassword", "test@somemail.com", ['readwrite']).ok);

      // Set up some ACL rules
      db.save({_id: '_local/_acl', rules: [
        {db: '*', role: '*', deny: '*'},
        {db: 'test_suite_db', role: 'read', allow: 'read'},
        {db: 'test_suite_db', role: 'write', allow: 'write'},
        {db: 'test_suite_db', role: 'readwrite', allow: 'read'},
        {db: 'test_suite_db', role: 'readwrite', allow: 'write'},
      ]});

      try {
        db.save({_id: 'testdoc'});
        T(false && "Can't get here. Should have thrown an error");
      } catch (e) {
        T(e.error == "unauthorized");
        T(db.last_req.status == 401);
      }
    });
};
