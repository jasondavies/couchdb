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

  function oauthRequest(path, params, method) {
    var d = [];
    if (method == "POST" || method == "GET") {
      for (k in params) {
        d.push(encodeURIComponent(k) + '=' + encodeURIComponent(encodeURIComponent(params[k])));
      }
      if (method == "GET") {
        return CouchDB.request("GET", path + '?' + d.join('&'));
      } else {
        return CouchDB.request("POST", path, {
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: d.join('&')
        });
      }
    } else {
      for (k in params) {
        d.push(encodeURIComponent(k) + '="' + encodeURIComponent(encodeURIComponent(params[k])) + '"');
      }
      return CouchDB.request("GET", path, {
        headers: {Authorization: 'OAuth ' + d.join(', ')}
      });
    }
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

      oauthParams = {
        oauth_signature: "secret&",
        oauth_signature_method: "PLAINTEXT",
        oauth_consumer_key: "key",
        oauth_version: "1.0"
      }

      // Get request token via Authorization header
      xhr = oauthRequest("/_oauth/request_token", oauthParams);
      T(xhr.status == 200);

      // POST request token
      xhr = oauthRequest("/_oauth/request_token", oauthParams, "POST");
      T(xhr.status == 200);

      // GET request token
      xhr = oauthRequest("/_oauth/request_token", oauthParams, "GET");
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
