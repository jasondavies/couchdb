// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations under
// the License.

couchTests.oauth = function(debug) {
  // This tests OAuth authentication.
  
  var db = new CouchDB("test_suite_db");
  db.deleteDb();
  db.createDb();
  if (debug) debugger;

  // Simple secret key generator
  function generateSecret(length) {
    var secret = '';
    for (var i=0; i<length; i++) {
      secret += String.fromCharCode(Math.floor(Math.random() * 256));
    }
    return secret;
  }
  // this function will be called on the modified server
  var testFun = function () {
    try {
      // try using an invalid cookie
      var usersDb = new CouchDB("test_suite_users");
      usersDb.deleteDb();
      usersDb.createDb();
      
      // Create a user
      T(usersDb.save({
        _id: "a1",
        salt: "123",
        password_sha: "8da1CtkFvb58LWrnup5chgdZVUs=",
        username: "Jason Davies",
        author: "Jason Davies",
        type: "user",
        roles: ["_admin"]
      }).ok);

      // Get request token
      xhr = CouchDB.request("GET", "/_oauth/request_token?oauth_signature=secret%2526&oauth_signature_method=PLAINTEXT&oauth_consumer_key=key", {
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
      });
      T(xhr.status == 200);

    } finally {
    }
  };

  run_on_modified_server(
    [{section: "httpd",
      key: "authentication_handler",
      value: "{couch_httpd_oauth, oauth_authentication_handler}"},
     {section: "couch_httpd_auth",
      key: "secret", value: generateSecret(64)},
     {section: "couch_httpd_auth",
      key: "authentication_db", value: "test_suite_users"}],
    testFun
  );
};
