% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_httpd_oauth).
-include("couch_db.hrl").

-export([handle_oauth_request/1]).

-import(couch_httpd, [header_value/2, send_json/4, send_method_not_allowed/2]).
-import(erlang, [integer_to_list/2, list_to_integer/2]).
-import(proplists, [get_value/2]).

handle_oauth_request(Request) ->
    null.

serve_oauth_request_token(Request) ->
    case Request:get(method) of
        'GET' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "GET", URL, Params, Consumer, "") of
                    true ->
                        ok(Request, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Request, "invalid signature value.")
                end
            end);
        _ ->
            method_not_allowed(Request)
    end.

serve_oauth_access_token(Request) ->
    case Request:get(method) of
        'GET' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:token(Params) of
                    "requestkey" ->
                        case oauth:verify(Signature, "GET", URL, Params, Consumer, "requestsecret") of
                            true ->
                                ok(Request, <<"oauth_token=accesskey&oauth_token_secret=accesssecret">>);
                            false ->
                                bad(Request, "invalid signature value.")
                        end;
                    _ ->
                        bad(Request, "invalid oauth token.")
                end
            end);
        _ ->
            method_not_allowed(Request)
    end.

serve_echo(Request) ->
    case Request:get(method) of
        'GET' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:token(Params) of
                    "accesskey" ->
                        case oauth:verify(Signature, "GET", URL, Params, Consumer, "accesssecret") of
                            true ->
                                EchoParams = lists:filter(fun({K, _}) -> not lists:prefix("oauth_", K) end, Params),
                                ok(Request, oauth_uri:params_to_string(EchoParams));
                            false ->
                                bad(Request, "invalid signature value.")
                        end;
                    _ ->
                        bad(Request, "invalid oauth token")
                end
            end);
        _ ->
            method_not_allowed(Request)
    end.
 
serve_oauth(Request, Fun) ->
    Params = Request:parse_qs(),
    case get_value("oauth_version", Params) of
        "1.0" ->
            ConsumerKey = get_value("oauth_consumer_key", Params),
            SigMethod = get_value("oauth_signature_method", Params),
            case consumer_lookup(ConsumerKey, SigMethod) of
                none ->
                    bad(Request, "invalid consumer (key or signature method).");
                Consumer ->
                    Signature = proplists:get_value("oauth_signature", Params),
                    URL = string:concat("http://0.0.0.0:8000", Request:get(path)),
                    Fun(URL, proplists:delete("oauth_signature", Params), Consumer, Signature)
            end;
        _ ->
            bad(Request, "invalid oauth version.")
    end.

consumer_lookup("key", "PLAINTEXT") ->
    {"key", "secret", plaintext};
consumer_lookup("key", "HMAC-SHA1") ->
    {"key", "secret", hmac_sha1};
consumer_lookup("key", "RSA-SHA1") ->
    {"key", "data/rsa_cert.pem", rsa_sha1};
consumer_lookup(_, _) ->
    none.

ok(Request, Body) ->
    Request:respond({200, [], Body}).

bad(Request, Reason) ->
    Request:respond({400, [], list_to_binary("Bad Request: " ++ Reason)}).

method_not_allowed(Request) ->
    Request:respond({405, [], <<>>}).
